//! QUIC Connection ID management and rotation
//!
//! Implements RFC 9000 connection ID management including:
//! - Connection ID generation and validation
//! - Active connection ID tracking
//! - Connection ID rotation and retirement
//! - Stateless reset token management

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use bytes::Bytes;
use crate::{QuicResult, QuicError};

/// Maximum length of a connection ID (RFC 9000)
pub const MAX_CONNECTION_ID_LENGTH: usize = 20;

/// Minimum recommended length for connection IDs
pub const MIN_CONNECTION_ID_LENGTH: usize = 4;

/// Default connection ID length
pub const DEFAULT_CONNECTION_ID_LENGTH: usize = 8;

/// Stateless reset token length (128 bits)
pub const STATELESS_RESET_TOKEN_LENGTH: usize = 16;

/// Connection ID with associated metadata
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionId {
    /// The connection ID bytes
    pub data: Bytes,
    /// Sequence number for this connection ID
    pub sequence_number: u64,
    /// When this connection ID was created
    pub created_at: Instant,
    /// When this connection ID was last used
    pub last_used: Option<Instant>,
    /// Whether this connection ID has been retired
    pub retired: bool,
}

impl ConnectionId {
    /// Create a new connection ID
    pub fn new(data: Bytes, sequence_number: u64) -> Self {
        Self {
            data,
            sequence_number,
            created_at: Instant::now(),
            last_used: None,
            retired: false,
        }
    }

    /// Generate a random connection ID
    pub fn generate_random(length: usize, sequence_number: u64) -> QuicResult<Self> {
        if length > MAX_CONNECTION_ID_LENGTH {
            return Err(QuicError::Protocol(format!(
                "Connection ID length {} exceeds maximum {}",
                length, MAX_CONNECTION_ID_LENGTH
            )));
        }

        let mut data = vec![0u8; length];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut data);

        Ok(Self::new(Bytes::from(data), sequence_number))
    }

    /// Create from raw bytes
    pub fn from_bytes(data: Vec<u8>, sequence_number: u64) -> QuicResult<Self> {
        if data.len() > MAX_CONNECTION_ID_LENGTH {
            return Err(QuicError::Protocol(format!(
                "Connection ID length {} exceeds maximum {}",
                data.len(), MAX_CONNECTION_ID_LENGTH
            )));
        }

        Ok(Self::new(Bytes::from(data), sequence_number))
    }

    /// Get the connection ID as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Get the length of the connection ID
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the connection ID is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Mark this connection ID as used
    pub fn mark_used(&mut self) {
        self.last_used = Some(Instant::now());
    }

    /// Mark this connection ID as retired
    pub fn retire(&mut self) {
        self.retired = true;
    }

    /// Check if this connection ID is retired
    pub fn is_retired(&self) -> bool {
        self.retired
    }

    /// Get age of this connection ID
    pub fn age(&self) -> Duration {
        Instant::now().duration_since(self.created_at)
    }

    /// Get time since last use
    pub fn time_since_last_use(&self) -> Option<Duration> {
        self.last_used.map(|last_used| Instant::now().duration_since(last_used))
    }
}

/// Stateless reset token for connection IDs
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StatelessResetToken([u8; STATELESS_RESET_TOKEN_LENGTH]);

impl StatelessResetToken {
    /// Create a new stateless reset token
    pub fn new(data: [u8; STATELESS_RESET_TOKEN_LENGTH]) -> Self {
        Self(data)
    }

    /// Generate a random stateless reset token
    pub fn generate_random() -> Self {
        let mut data = [0u8; STATELESS_RESET_TOKEN_LENGTH];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut data);
        Self(data)
    }

    /// Derive a stateless reset token from a connection ID and secret
    pub fn derive_from_connection_id(connection_id: &ConnectionId, secret: &[u8]) -> QuicResult<Self> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(secret)
            .map_err(|e| QuicError::Crypto(format!("Invalid key length: {}", e)))?;

        mac.update(connection_id.as_bytes());
        let result = mac.finalize();
        let mut token = [0u8; STATELESS_RESET_TOKEN_LENGTH];
        token.copy_from_slice(&result.into_bytes()[..STATELESS_RESET_TOKEN_LENGTH]);

        Ok(Self(token))
    }

    /// Get the token as bytes
    pub fn as_bytes(&self) -> &[u8; STATELESS_RESET_TOKEN_LENGTH] {
        &self.0
    }
}

/// Connection ID manager handles active connection IDs and rotation
#[derive(Debug)]
pub struct ConnectionIdManager {
    /// Currently active connection IDs (indexed by sequence number)
    active_ids: HashMap<u64, ConnectionId>,
    /// Retired connection IDs (for grace period)
    retired_ids: VecDeque<ConnectionId>,
    /// Stateless reset tokens for active connection IDs
    reset_tokens: HashMap<u64, StatelessResetToken>,
    /// Secret for generating stateless reset tokens
    reset_token_secret: Vec<u8>,
    /// Next sequence number to assign
    next_sequence_number: u64,
    /// Maximum number of active connection IDs
    max_active_ids: usize,
    /// Maximum number of retired IDs to keep
    max_retired_ids: usize,
    /// How long to keep retired IDs
    retirement_grace_period: Duration,
    /// How often to rotate connection IDs
    rotation_interval: Duration,
    /// Last rotation time
    last_rotation: Option<Instant>,
    /// Preferred connection ID length
    preferred_length: usize,
}

impl ConnectionIdManager {
    /// Create a new connection ID manager
    pub fn new() -> Self {
        let mut reset_token_secret = vec![0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut reset_token_secret);

        Self {
            active_ids: HashMap::new(),
            retired_ids: VecDeque::new(),
            reset_tokens: HashMap::new(),
            reset_token_secret,
            next_sequence_number: 0,
            max_active_ids: 8, // RFC recommended
            max_retired_ids: 16,
            retirement_grace_period: Duration::from_secs(30),
            rotation_interval: Duration::from_secs(300), // 5 minutes
            last_rotation: None,
            preferred_length: DEFAULT_CONNECTION_ID_LENGTH,
        }
    }

    /// Create with custom parameters
    pub fn with_params(
        max_active_ids: usize,
        rotation_interval: Duration,
        preferred_length: usize,
    ) -> Self {
        let mut manager = Self::new();
        manager.max_active_ids = max_active_ids;
        manager.rotation_interval = rotation_interval;
        manager.preferred_length = preferred_length.min(MAX_CONNECTION_ID_LENGTH);
        manager
    }

    /// Generate a new connection ID
    pub fn generate_new_id(&mut self) -> QuicResult<(ConnectionId, StatelessResetToken)> {
        // Clean up old retired IDs first
        self.cleanup_retired_ids();

        // Check if we have room for a new active ID
        if self.active_ids.len() >= self.max_active_ids {
            // Retire the oldest active ID
            if let Some(oldest_seq) = self.find_oldest_active_id() {
                self.retire_connection_id(oldest_seq)?;
            }
        }

        let sequence_number = self.next_sequence_number;
        self.next_sequence_number += 1;

        // Generate the connection ID
        let connection_id = ConnectionId::generate_random(self.preferred_length, sequence_number)?;

        // Generate stateless reset token
        let reset_token = StatelessResetToken::derive_from_connection_id(
            &connection_id, &self.reset_token_secret
        )?;

        // Store them
        self.active_ids.insert(sequence_number, connection_id.clone());
        self.reset_tokens.insert(sequence_number, reset_token.clone());

        Ok((connection_id, reset_token))
    }

    /// Add an externally provided connection ID
    pub fn add_connection_id(
        &mut self,
        connection_id: ConnectionId,
        reset_token: Option<StatelessResetToken>,
    ) -> QuicResult<()> {
        let sequence_number = connection_id.sequence_number;

        // Generate reset token if not provided
        let reset_token = match reset_token {
            Some(token) => token,
            None => StatelessResetToken::derive_from_connection_id(
                &connection_id, &self.reset_token_secret
            )?,
        };

        self.active_ids.insert(sequence_number, connection_id);
        self.reset_tokens.insert(sequence_number, reset_token);

        Ok(())
    }

    /// Retire a connection ID by sequence number
    pub fn retire_connection_id(&mut self, sequence_number: u64) -> QuicResult<()> {
        if let Some(mut connection_id) = self.active_ids.remove(&sequence_number) {
            connection_id.retire();
            self.retired_ids.push_back(connection_id);
            self.reset_tokens.remove(&sequence_number);

            // Keep only the most recent retired IDs
            while self.retired_ids.len() > self.max_retired_ids {
                self.retired_ids.pop_front();
            }

            Ok(())
        } else {
            Err(QuicError::Protocol(format!(
                "Connection ID with sequence number {} not found", sequence_number
            )))
        }
    }

    /// Mark a connection ID as used
    pub fn mark_connection_id_used(&mut self, connection_id_bytes: &[u8]) -> bool {
        for connection_id in self.active_ids.values_mut() {
            if connection_id.as_bytes() == connection_id_bytes {
                connection_id.mark_used();
                return true;
            }
        }
        false
    }

    /// Find a connection ID by its bytes
    pub fn find_connection_id(&self, connection_id_bytes: &[u8]) -> Option<&ConnectionId> {
        self.active_ids.values()
            .find(|id| id.as_bytes() == connection_id_bytes)
    }

    /// Get all active connection IDs
    pub fn active_connection_ids(&self) -> Vec<&ConnectionId> {
        self.active_ids.values().collect()
    }

    /// Get the preferred (most recently generated) connection ID
    pub fn preferred_connection_id(&self) -> Option<&ConnectionId> {
        self.active_ids.values()
            .max_by_key(|id| id.sequence_number)
    }

    /// Check if it's time to rotate connection IDs
    pub fn should_rotate(&self) -> bool {
        match self.last_rotation {
            Some(last_rotation) => {
                Instant::now().duration_since(last_rotation) >= self.rotation_interval
            }
            None => true, // Never rotated, should do initial rotation
        }
    }

    /// Perform connection ID rotation
    pub fn rotate_connection_ids(&mut self) -> QuicResult<Vec<(ConnectionId, StatelessResetToken)>> {
        let mut new_ids = Vec::new();

        // Generate new connection IDs to replace old ones
        let target_count = (self.max_active_ids / 2).max(1); // Replace half, at least one

        for _ in 0..target_count {
            let (new_id, reset_token) = self.generate_new_id()?;
            new_ids.push((new_id, reset_token));
        }

        self.last_rotation = Some(Instant::now());
        Ok(new_ids)
    }

    /// Find the oldest active connection ID
    fn find_oldest_active_id(&self) -> Option<u64> {
        self.active_ids.iter()
            .min_by_key(|(_, id)| id.created_at)
            .map(|(seq, _)| *seq)
    }

    /// Clean up old retired connection IDs
    fn cleanup_retired_ids(&mut self) {
        let cutoff = Instant::now() - self.retirement_grace_period;

        while let Some(retired_id) = self.retired_ids.front() {
            if retired_id.created_at < cutoff {
                self.retired_ids.pop_front();
            } else {
                break;
            }
        }
    }

    /// Get stateless reset token for a connection ID
    pub fn get_reset_token(&self, sequence_number: u64) -> Option<&StatelessResetToken> {
        self.reset_tokens.get(&sequence_number)
    }

    /// Check if a stateless reset token is valid
    pub fn is_valid_reset_token(&self, token: &StatelessResetToken) -> bool {
        self.reset_tokens.values().any(|t| t == token)
    }

    /// Get connection ID manager statistics
    pub fn stats(&self) -> ConnectionIdStats {
        ConnectionIdStats {
            active_count: self.active_ids.len(),
            retired_count: self.retired_ids.len(),
            next_sequence_number: self.next_sequence_number,
            last_rotation: self.last_rotation,
            time_since_last_rotation: self.last_rotation
                .map(|t| Instant::now().duration_since(t)),
        }
    }

    /// Set the rotation interval
    pub fn set_rotation_interval(&mut self, interval: Duration) {
        self.rotation_interval = interval;
    }

    /// Set the preferred connection ID length
    pub fn set_preferred_length(&mut self, length: usize) {
        self.preferred_length = length.min(MAX_CONNECTION_ID_LENGTH);
    }
}

/// Statistics for connection ID management
#[derive(Debug, Clone)]
pub struct ConnectionIdStats {
    pub active_count: usize,
    pub retired_count: usize,
    pub next_sequence_number: u64,
    pub last_rotation: Option<Instant>,
    pub time_since_last_rotation: Option<Duration>,
}

impl Default for ConnectionIdManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_id_creation() {
        let id = ConnectionId::generate_random(8, 0).unwrap();
        assert_eq!(id.len(), 8);
        assert_eq!(id.sequence_number, 0);
        assert!(!id.is_retired());
    }

    #[test]
    fn test_connection_id_manager() {
        let mut manager = ConnectionIdManager::new();

        // Generate a new connection ID
        let (id1, token1) = manager.generate_new_id().unwrap();
        assert_eq!(manager.stats().active_count, 1);

        // Find the connection ID
        let found = manager.find_connection_id(id1.as_bytes());
        assert!(found.is_some());

        // Generate another ID
        let (id2, token2) = manager.generate_new_id().unwrap();
        assert_eq!(manager.stats().active_count, 2);
        assert_ne!(id1.as_bytes(), id2.as_bytes());
    }

    #[test]
    fn test_connection_id_retirement() {
        let mut manager = ConnectionIdManager::new();
        let (id, _token) = manager.generate_new_id().unwrap();
        let seq_num = id.sequence_number;

        // Retire the connection ID
        manager.retire_connection_id(seq_num).unwrap();
        assert_eq!(manager.stats().active_count, 0);
        assert_eq!(manager.stats().retired_count, 1);

        // Should not find the retired ID in active IDs
        let found = manager.find_connection_id(id.as_bytes());
        assert!(found.is_none());
    }

    #[test]
    fn test_stateless_reset_token() {
        let token1 = StatelessResetToken::generate_random();
        let token2 = StatelessResetToken::generate_random();
        assert_ne!(token1.as_bytes(), token2.as_bytes());

        // Test derivation from connection ID
        let id = ConnectionId::generate_random(8, 0).unwrap();
        let secret = b"test_secret_key_for_reset_tokens";
        let derived_token = StatelessResetToken::derive_from_connection_id(&id, secret).unwrap();

        // Deriving again should give the same result
        let derived_token2 = StatelessResetToken::derive_from_connection_id(&id, secret).unwrap();
        assert_eq!(derived_token.as_bytes(), derived_token2.as_bytes());
    }

    #[test]
    fn test_rotation() {
        let mut manager = ConnectionIdManager::with_params(
            4, // max_active_ids
            Duration::from_millis(100), // rotation_interval
            8, // preferred_length
        );

        // Should need rotation initially
        assert!(manager.should_rotate());

        // Perform rotation
        let new_ids = manager.rotate_connection_ids().unwrap();
        assert!(!new_ids.is_empty());
        assert!(!manager.should_rotate()); // Should not need rotation immediately after

        // Wait and check again
        std::thread::sleep(Duration::from_millis(150));
        assert!(manager.should_rotate());
    }
}