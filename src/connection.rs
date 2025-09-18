//! QUIC connection management

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

use crate::crypto::{CryptoBackend, default_crypto_backend, SharedSecret};
use crate::handshake::QuicHandshake;
use crate::connection_state::{ConnectionState, ConnectionStateManager};
use crate::idle_timeout::IdleTimeoutManager;
use crate::version_negotiation::{VersionNegotiationManager, QuicVersion};
use crate::state_machine::{QuicStateMachine, StateEvent};
use crate::error_recovery::{ErrorRecoveryManager, RecoveryStrategy};
use crate::frame::Frame;
use crate::QuicResult;

// Re-export the comprehensive ConnectionId from connection_id module
pub use crate::connection_id::{ConnectionId, ConnectionIdManager, StatelessResetToken};

#[derive(Debug, Clone)]
pub struct Connection {
    id: ConnectionId,
    remote_addr: SocketAddr,
    socket: Arc<UdpSocket>,
    crypto_backend: Arc<dyn CryptoBackend>,
    handshake: Option<QuicHandshake>,
    shared_secret: Option<SharedSecret>,
    state_manager: ConnectionStateManager,
    idle_timeout_manager: IdleTimeoutManager,
    version_manager: VersionNegotiationManager,
    state_machine: QuicStateMachine,
    error_recovery: ErrorRecoveryManager,
    connection_id_manager: ConnectionIdManager,
    close_sent: bool,
    drain_timeout: std::time::Duration,
}

impl Connection {
    pub fn new(id: ConnectionId, remote_addr: SocketAddr, socket: Arc<UdpSocket>) -> Self {
        Self {
            id,
            remote_addr,
            socket,
            crypto_backend: default_crypto_backend(),
            handshake: None,
            shared_secret: None,
            state_manager: ConnectionStateManager::new(),
            idle_timeout_manager: IdleTimeoutManager::new(std::time::Duration::from_secs(30)),
            version_manager: VersionNegotiationManager::new(),
            state_machine: QuicStateMachine::new(),
            error_recovery: ErrorRecoveryManager::new(),
            connection_id_manager: ConnectionIdManager::new(),
            close_sent: false,
            drain_timeout: std::time::Duration::from_secs(3), // 3-second drain timeout
        }
    }
    
    pub fn with_crypto_backend(
        id: ConnectionId,
        remote_addr: SocketAddr,
        socket: Arc<UdpSocket>,
        crypto_backend: Arc<dyn CryptoBackend>
    ) -> Self {
        Self {
            id,
            remote_addr,
            socket,
            crypto_backend,
            handshake: None,
            shared_secret: None,
            state_manager: ConnectionStateManager::new(),
            idle_timeout_manager: IdleTimeoutManager::new(std::time::Duration::from_secs(30)),
            version_manager: VersionNegotiationManager::new(),
            state_machine: QuicStateMachine::new(),
            error_recovery: ErrorRecoveryManager::new(),
            connection_id_manager: ConnectionIdManager::new(),
            close_sent: false,
            drain_timeout: std::time::Duration::from_secs(3),
        }
    }
    
    pub fn id(&self) -> &ConnectionId {
        &self.id
    }
    
    /// Initialize handshake for this connection
    pub fn init_handshake(&mut self) -> QuicResult<()> {
        // Use state machine for proper transition
        self.state_machine.transition(StateEvent::HandshakeStarted)?;
        self.state_manager.start_handshake()?;

        self.handshake = Some(QuicHandshake::with_crypto_backend(
            self.id.clone(),
            self.crypto_backend.clone()
        ));
        Ok(())
    }
    
    /// Get mutable reference to handshake
    pub fn handshake_mut(&mut self) -> Option<&mut QuicHandshake> {
        self.handshake.as_mut()
    }
    
    /// Check if handshake is established and update connection state
    pub fn update_crypto_state(&mut self) -> QuicResult<()> {
        if let Some(handshake) = &self.handshake {
            if handshake.is_established() {
                self.shared_secret = handshake.shared_secret().cloned();

                // Update state machines if handshake completed
                if matches!(self.state_machine.current_state(), ConnectionState::Handshaking) {
                    self.state_machine.transition(StateEvent::HandshakeCompleted)?;
                    self.state_manager.handshake_complete()?;
                }
            }
        }
        Ok(())
    }
    
    pub async fn send(&self, data: &[u8]) -> QuicResult<()> {
        self.socket.send_to(data, self.remote_addr).await?;
        Ok(())
    }
    
    /// Send data with real GCC encryption
    pub async fn send_encrypted(&self, data: &[u8]) -> QuicResult<()> {
        if let Some(handshake) = &self.handshake {
            if handshake.is_established() {
                let encrypted_data = handshake.encrypt_data(data)?;
                self.socket.send_to(&encrypted_data, self.remote_addr).await?;
                Ok(())
            } else {
                Err(crate::QuicError::Crypto("Handshake not established".to_string()))
            }
        } else {
            Err(crate::QuicError::Crypto("No handshake initialized".to_string()))
        }
    }
    
    /// Send data with legacy key-based encryption (for compatibility)
    pub async fn send_encrypted_with_key(&self, data: &[u8], key: &[u8]) -> QuicResult<()> {
        if key.len() < 32 {
            return Err(crate::QuicError::Crypto("Key too short".to_string()));
        }
        
        let shared_secret = SharedSecret({
            let mut secret = [0u8; 32];
            secret.copy_from_slice(&key[..32]);
            secret
        });
        
        let nonce = self.crypto_backend.generate_nonce()?;
        let encrypted_data = self.crypto_backend.encrypt(data, &shared_secret, &nonce)?;
        
        // Append nonce to encrypted data
        let mut payload = encrypted_data;
        payload.extend_from_slice(&nonce);
        
        self.socket.send_to(&payload, self.remote_addr).await?;
        Ok(())
    }
    
    /// Receive and decrypt data using established handshake
    pub async fn receive_decrypted(&self) -> QuicResult<Vec<u8>> {
        let mut buf = vec![0u8; 65535];
        let (len, _) = self.socket.recv_from(&mut buf).await?;
        buf.truncate(len);
        
        if let Some(handshake) = &self.handshake {
            if handshake.is_established() {
                handshake.decrypt_data(&buf)
            } else {
                Err(crate::QuicError::Crypto("Handshake not established".to_string()))
            }
        } else {
            Err(crate::QuicError::Crypto("No handshake initialized".to_string()))
        }
    }
    
    /// Receive and decrypt data with legacy key-based decryption (for compatibility)
    pub async fn receive_decrypted_with_key(&self, key: &[u8]) -> QuicResult<Vec<u8>> {
        let mut buf = vec![0u8; 65535];
        let (len, _) = self.socket.recv_from(&mut buf).await?;
        buf.truncate(len);
        
        if buf.len() < 12 {
            return Err(crate::QuicError::Crypto("Data too short for nonce".to_string()));
        }
        
        if key.len() < 32 {
            return Err(crate::QuicError::Crypto("Key too short".to_string()));
        }
        
        let shared_secret = SharedSecret({
            let mut secret = [0u8; 32];
            secret.copy_from_slice(&key[..32]);
            secret
        });
        
        // Extract nonce from end of payload
        let (encrypted_data, nonce) = buf.split_at(buf.len() - 12);
        let decrypted_data = self.crypto_backend.decrypt(encrypted_data, &shared_secret, nonce)?;
        Ok(decrypted_data)
    }
    
    /// Gracefully close the connection with a CONNECTION_CLOSE frame
    pub async fn close_gracefully(&mut self, error_code: u64, reason: &str) -> QuicResult<()> {
        if self.close_sent {
            return Ok(()); // Already closing
        }

        // Use state machine for proper transition
        self.state_machine.transition(StateEvent::CloseSent {
            error_code,
            reason: reason.to_string(),
        })?;

        // Update legacy state manager
        self.state_manager.close(error_code, reason.to_string());
        self.close_sent = true;

        // Create CONNECTION_CLOSE frame
        let close_frame = Frame::ConnectionClose {
            error_code,
            frame_type: None,
            reason_phrase: reason.to_string(),
        };

        // Send the close frame
        let encoded_frame = close_frame.encode_crypto();
        self.socket.send_to(&encoded_frame, self.remote_addr).await?;

        // Start drain timer
        tokio::spawn({
            let socket = self.socket.clone();
            let remote_addr = self.remote_addr;
            let drain_timeout = self.drain_timeout;
            async move {
                tokio::time::sleep(drain_timeout).await;
                // Connection is now fully closed after drain period
            }
        });

        Ok(())
    }

    /// Send APPLICATION_CLOSE frame for application-level errors
    pub async fn close_application(&mut self, error_code: u64, reason: &str) -> QuicResult<()> {
        if self.close_sent {
            return Ok(());
        }

        self.state_manager.close(error_code, reason.to_string());
        self.close_sent = true;

        let close_frame = Frame::ApplicationClose {
            error_code,
            reason_phrase: reason.to_string(),
        };

        let encoded_frame = close_frame.encode_crypto();
        self.socket.send_to(&encoded_frame, self.remote_addr).await?;

        Ok(())
    }

    /// Handle received CONNECTION_CLOSE frame
    pub fn handle_connection_close(&mut self, error_code: u64, reason: &str) -> QuicResult<()> {
        // Use state machine for proper transition
        self.state_machine.transition(StateEvent::CloseReceived {
            error_code,
            reason: reason.to_string(),
        })?;

        // Update legacy state manager
        self.state_manager.enter_draining(error_code, reason.to_string());
        Ok(())
    }

    /// Handle received APPLICATION_CLOSE frame
    pub fn handle_application_close(&mut self, error_code: u64, reason: &str) -> QuicResult<()> {
        // Use state machine for proper transition
        self.state_machine.transition(StateEvent::CloseReceived {
            error_code,
            reason: reason.to_string(),
        })?;

        self.state_manager.enter_draining(error_code, reason.to_string());
        Ok(())
    }

    /// Check if connection is in draining state
    pub fn is_draining(&self) -> bool {
        self.state_manager.is_draining()
    }

    /// Check if connection is closing or draining
    pub fn is_closing_or_draining(&self) -> bool {
        self.state_manager.is_closing_or_draining()
    }

    /// Check if connection can still send data
    pub fn can_send_data(&self) -> bool {
        self.state_manager.can_send_data() && !self.close_sent
    }

    /// Update connection activity and check timeouts
    pub async fn update_activity(&mut self) -> QuicResult<()> {
        self.state_manager.mark_active();
        self.idle_timeout_manager.mark_activity();

        // Check idle timeout first
        if let Err(e) = self.idle_timeout_manager.check_idle_timeout() {
            // Close connection due to idle timeout
            self.close_gracefully(0x0, "Idle timeout").await?;
            return Err(e);
        }

        // Check other connection state timeouts
        self.state_manager.check_timeouts()
    }

    /// Check if we should send a keep-alive PING
    pub async fn check_keepalive(&mut self) -> QuicResult<()> {
        if self.idle_timeout_manager.should_send_keepalive() {
            let ping_frame = self.idle_timeout_manager.create_keepalive_frame();
            let encoded_frame = ping_frame.encode_crypto();
            self.socket.send_to(&encoded_frame, self.remote_addr).await?;
            self.idle_timeout_manager.mark_activity(); // Mark activity for sent PING
        }
        Ok(())
    }

    /// Add RTT measurement for adaptive timeout
    pub fn add_rtt_measurement(&mut self, rtt: std::time::Duration) {
        self.idle_timeout_manager.add_rtt_measurement(rtt);
    }

    /// Configure idle timeout
    pub fn set_idle_timeout(&mut self, timeout: std::time::Duration) {
        self.idle_timeout_manager.reset_timeout(timeout);
    }

    /// Get idle timeout statistics
    pub fn idle_timeout_stats(&self) -> crate::idle_timeout::IdleTimeoutStats {
        self.idle_timeout_manager.stats()
    }

    /// Handle version negotiation for incoming packets
    pub async fn handle_version_negotiation(&mut self, proposed_version: QuicVersion) -> QuicResult<()> {
        use crate::version_negotiation::VersionNegotiationResult;

        match self.version_manager.handle_initial_version(proposed_version)? {
            VersionNegotiationResult::Accepted(version) => {
                // Version accepted, continue with connection setup
                Ok(())
            }
            VersionNegotiationResult::Rejected { supported_versions } => {
                // Send version negotiation packet
                let vn_packet = self.version_manager.create_version_negotiation_packet(
                    self.id.0.clone(),
                    self.id.0.clone(), // Using same for both for now
                );
                let encoded_packet = vn_packet.encode();
                self.socket.send_to(&encoded_packet, self.remote_addr).await?;
                Err(crate::QuicError::Protocol("Version negotiation required".to_string()))
            }
        }
    }

    /// Get the negotiated QUIC version
    pub fn negotiated_version(&self) -> Option<QuicVersion> {
        self.version_manager.current_version()
    }

    /// Check if version negotiation is complete
    pub fn is_version_negotiated(&self) -> bool {
        self.version_manager.is_complete()
    }

    /// Get supported QUIC versions
    pub fn supported_versions(&self) -> &[QuicVersion] {
        self.version_manager.supported_versions()
    }

    /// Force a specific QUIC version (for testing)
    pub fn force_version(&mut self, version: QuicVersion) {
        self.version_manager.force_version(version);
    }

    /// Get state machine statistics
    pub fn state_machine_stats(&self) -> crate::state_machine::StateMachineStats {
        self.state_machine.stats()
    }

    /// Check if connection can send data (using state machine)
    pub fn can_send_data_sm(&self) -> bool {
        self.state_machine.can_send_data()
    }

    /// Check if connection can receive data (using state machine)
    pub fn can_receive_data_sm(&self) -> bool {
        self.state_machine.can_receive_data()
    }

    /// Check if connection is in terminal state
    pub fn is_terminal(&self) -> bool {
        self.state_machine.is_terminal()
    }

    /// Get the number of state transitions
    pub fn transition_count(&self) -> usize {
        self.state_machine.transition_count()
    }

    /// Get time spent in current state
    pub fn time_in_current_state(&self) -> std::time::Duration {
        self.state_machine.time_in_current_state()
    }

    /// Handle connection errors through state machine
    pub fn handle_connection_error(&mut self, error: &str) -> QuicResult<()> {
        self.state_machine.transition(StateEvent::ConnectionError {
            error: error.to_string(),
        })?;
        self.state_manager.fail(error.to_string());
        Ok(())
    }

    /// Handle any error with comprehensive recovery
    pub async fn handle_error_with_recovery(&mut self, error: crate::QuicError) -> QuicResult<bool> {
        // Use error recovery manager to determine strategy
        let recovery_strategy = self.error_recovery.handle_error(error)?;

        match recovery_strategy {
            RecoveryStrategy::Ignore => {
                // Log and continue
                Ok(true)
            }
            RecoveryStrategy::Retry { max_attempts, base_delay, max_delay } => {
                // Implement retry logic with exponential backoff
                tokio::time::sleep(base_delay).await;
                Ok(true) // Should retry
            }
            RecoveryStrategy::Reset => {
                // Reset connection state
                self.reset_connection_state()?;
                Ok(true)
            }
            RecoveryStrategy::Migrate => {
                // TODO: Implement path migration
                self.close_gracefully(0x0, "Migration required").await?;
                Ok(false)
            }
            RecoveryStrategy::CloseGraceful { error_code } => {
                self.close_gracefully(error_code, "Recoverable error, closing gracefully").await?;
                Ok(false)
            }
            RecoveryStrategy::CloseImmediate { error_code } => {
                self.close_application(error_code, "Critical error, closing immediately").await?;
                Ok(false)
            }
            RecoveryStrategy::RestartEndpoint => {
                // This would be handled at a higher level
                Err(crate::QuicError::Protocol("Endpoint restart required".to_string()))
            }
        }
    }

    /// Reset connection state for recovery
    fn reset_connection_state(&mut self) -> QuicResult<()> {
        // Reset various components
        self.handshake = None;
        self.shared_secret = None;
        self.close_sent = false;

        // Reset state managers
        self.state_manager = crate::connection_state::ConnectionStateManager::new();
        self.idle_timeout_manager = crate::idle_timeout::IdleTimeoutManager::new(std::time::Duration::from_secs(30));
        self.state_machine = crate::state_machine::QuicStateMachine::new();

        Ok(())
    }

    /// Get error recovery statistics
    pub fn error_recovery_stats(&self) -> crate::error_recovery::ErrorStats {
        self.error_recovery.get_error_stats()
    }

    /// Add a circuit breaker for a specific operation
    pub fn add_circuit_breaker(&mut self, name: String, circuit_breaker: crate::error_recovery::CircuitBreaker) {
        self.error_recovery.add_circuit_breaker(name, circuit_breaker);
    }

    /// Execute an operation with circuit breaker protection
    pub fn execute_with_circuit_breaker<F, T>(&mut self, name: &str, operation: F) -> QuicResult<T>
    where
        F: FnOnce() -> QuicResult<T>,
    {
        if let Some(circuit_breaker) = self.error_recovery.get_circuit_breaker_mut(name) {
            match circuit_breaker.call(operation) {
                Ok(result) => Ok(result),
                Err(error) => {
                    // Handle the error through our error recovery system
                    let _ = self.error_recovery.handle_error(error.clone());
                    Err(error)
                }
            }
        } else {
            // No circuit breaker, execute directly
            operation()
        }
    }

    /// Check connection health and recover if needed
    pub async fn health_check_and_recover(&mut self) -> QuicResult<()> {
        // Check various health indicators
        let mut issues = Vec::new();

        // Check state consistency
        if self.is_terminal() && !self.close_sent {
            issues.push("Connection in terminal state but close not sent");
        }

        // Check timeout violations
        if let Err(_) = self.idle_timeout_manager.check_idle_timeout() {
            issues.push("Idle timeout exceeded");
        }

        // Check error rate
        let error_stats = self.error_recovery_stats();
        if error_stats.error_rate > 10.0 { // More than 10 errors per second
            issues.push("High error rate detected");
        }

        // Attempt recovery for any issues found
        if !issues.is_empty() {
            for issue in issues {
                let error = crate::QuicError::Protocol(format!("Health check failed: {}", issue));
                let _ = self.handle_error_with_recovery(error).await?;
            }
        }

        Ok(())
    }

    /// Generate a new connection ID
    pub fn generate_new_connection_id(&mut self) -> QuicResult<(ConnectionId, StatelessResetToken)> {
        self.connection_id_manager.generate_new_id()
    }

    /// Retire a connection ID
    pub fn retire_connection_id(&mut self, sequence_number: u64) -> QuicResult<()> {
        self.connection_id_manager.retire_connection_id(sequence_number)
    }

    /// Mark a connection ID as used
    pub fn mark_connection_id_used(&mut self, connection_id_bytes: &[u8]) -> bool {
        self.connection_id_manager.mark_connection_id_used(connection_id_bytes)
    }

    /// Get all active connection IDs
    pub fn active_connection_ids(&self) -> Vec<&ConnectionId> {
        self.connection_id_manager.active_connection_ids()
    }

    /// Get the preferred connection ID
    pub fn preferred_connection_id(&self) -> Option<&ConnectionId> {
        self.connection_id_manager.preferred_connection_id()
    }

    /// Check if connection ID rotation is needed
    pub fn should_rotate_connection_ids(&self) -> bool {
        self.connection_id_manager.should_rotate()
    }

    /// Perform connection ID rotation
    pub async fn rotate_connection_ids(&mut self) -> QuicResult<Vec<Frame>> {
        let new_ids = self.connection_id_manager.rotate_connection_ids()?;

        // Create NEW_CONNECTION_ID frames for each new ID
        let mut frames = Vec::new();
        for (connection_id, reset_token) in new_ids {
            let frame = Frame::NewConnectionId {
                sequence_number: connection_id.sequence_number,
                retire_prior_to: 0, // Don't immediately retire old IDs
                connection_id: bytes::Bytes::copy_from_slice(connection_id.as_bytes()),
                stateless_reset_token: *reset_token.as_bytes(),
            };
            frames.push(frame);
        }

        // Send the frames
        for frame in &frames {
            let encoded_frame = frame.encode_crypto();
            self.socket.send_to(&encoded_frame, self.remote_addr).await?;
        }

        Ok(frames)
    }

    /// Handle a NEW_CONNECTION_ID frame
    pub fn handle_new_connection_id(
        &mut self,
        sequence_number: u64,
        retire_prior_to: u64,
        connection_id_bytes: bytes::Bytes,
        stateless_reset_token: [u8; 16],
    ) -> QuicResult<()> {
        // Create connection ID from received data
        let connection_id = ConnectionId::from_bytes(connection_id_bytes.to_vec(), sequence_number)?;
        let reset_token = StatelessResetToken::new(stateless_reset_token);

        // Add to our manager
        self.connection_id_manager.add_connection_id(connection_id, Some(reset_token))?;

        // Retire old connection IDs if requested
        for seq in 0..retire_prior_to {
            let _ = self.connection_id_manager.retire_connection_id(seq);
        }

        Ok(())
    }

    /// Handle a RETIRE_CONNECTION_ID frame
    pub fn handle_retire_connection_id(&mut self, sequence_number: u64) -> QuicResult<()> {
        self.connection_id_manager.retire_connection_id(sequence_number)
    }

    /// Get connection ID manager statistics
    pub fn connection_id_stats(&self) -> crate::connection_id::ConnectionIdStats {
        self.connection_id_manager.stats()
    }

    /// Configure connection ID rotation interval
    pub fn set_connection_id_rotation_interval(&mut self, interval: std::time::Duration) {
        self.connection_id_manager.set_rotation_interval(interval);
    }

    /// Check and perform automatic connection ID rotation if needed
    pub async fn check_and_rotate_connection_ids(&mut self) -> QuicResult<()> {
        if self.should_rotate_connection_ids() {
            let _ = self.rotate_connection_ids().await?;
        }
        Ok(())
    }

    /// Get connection state
    pub fn state(&self) -> &ConnectionState {
        self.state_manager.state()
    }

    /// Get connection statistics for monitoring
    pub fn stats(&self) -> ConnectionStats {
        ConnectionStats {
            id: self.id.clone(),
            remote_addr: self.remote_addr,
            packets_sent: 0, // Placeholder - would track in real implementation
            packets_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
            state: self.state_manager.state().clone(),
            close_sent: self.close_sent,
            connection_id_stats: self.connection_id_stats(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionStats {
    pub id: ConnectionId,
    pub remote_addr: SocketAddr,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub state: ConnectionState,
    pub close_sent: bool,
    pub connection_id_stats: crate::connection_id::ConnectionIdStats,
}
