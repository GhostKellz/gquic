//! QUIC connection state management

use crate::{QuicResult, QuicError};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionState {
    /// Initial state, no packets exchanged
    Initial,
    /// Handshake in progress
    Handshaking,
    /// Connection established and ready for data
    Active,
    /// Connection is being closed gracefully
    Closing {
        error_code: u64,
        reason: String,
        initiated_at: Instant,
    },
    /// Connection is in draining state (received close, waiting to send final packets)
    Draining {
        error_code: u64,
        reason: String,
        started_at: Instant,
        drain_timeout: Duration,
    },
    /// Connection has been closed
    Closed,
    /// Connection failed due to error
    Failed { 
        error: String,
        failed_at: Instant,
    },
}

/// QUIC connection state manager
pub struct ConnectionStateManager {
    state: ConnectionState,
    created_at: Instant,
    last_activity: Instant,
    idle_timeout: Duration,
    max_lifetime: Duration,
    drain_timeout: Duration,
}

impl ConnectionStateManager {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            state: ConnectionState::Initial,
            created_at: now,
            last_activity: now,
            idle_timeout: Duration::from_secs(30), // 30 second idle timeout
            max_lifetime: Duration::from_secs(3600), // 1 hour max lifetime
            drain_timeout: Duration::from_secs(3), // 3 second drain timeout
        }
    }
    
    pub fn with_timeouts(idle_timeout: Duration, max_lifetime: Duration) -> Self {
        let now = Instant::now();
        Self {
            state: ConnectionState::Initial,
            created_at: now,
            last_activity: now,
            idle_timeout,
            max_lifetime,
            drain_timeout: Duration::from_secs(3),
        }
    }

    pub fn with_all_timeouts(idle_timeout: Duration, max_lifetime: Duration, drain_timeout: Duration) -> Self {
        let now = Instant::now();
        Self {
            state: ConnectionState::Initial,
            created_at: now,
            last_activity: now,
            idle_timeout,
            max_lifetime,
            drain_timeout,
        }
    }
    
    /// Get current connection state
    pub fn state(&self) -> &ConnectionState {
        &self.state
    }
    
    /// Update connection state
    pub fn set_state(&mut self, new_state: ConnectionState) {
        self.state = new_state;
        self.last_activity = Instant::now();
    }
    
    /// Mark connection as active (data sent/received)
    pub fn mark_active(&mut self) {
        self.last_activity = Instant::now();
    }
    
    /// Check if connection should be closed due to timeout
    pub fn check_timeouts(&mut self) -> QuicResult<()> {
        let now = Instant::now();
        
        // Check drain timeout first if in draining state
        if let ConnectionState::Draining { started_at, drain_timeout, .. } = &self.state {
            if now.duration_since(*started_at) > *drain_timeout {
                self.state = ConnectionState::Closed;
                return Err(QuicError::ConnectionClosed);
            }
        }

        // Check idle timeout
        if now.duration_since(self.last_activity) > self.idle_timeout {
            match self.state {
                ConnectionState::Closed | ConnectionState::Failed { .. } | ConnectionState::Draining { .. } => {
                    // Already closed/failed/draining, nothing to do
                }
                _ => {
                    self.state = ConnectionState::Closing {
                        error_code: 0x0, // NO_ERROR
                        reason: "Idle timeout".to_string(),
                        initiated_at: now,
                    };
                    return Err(QuicError::ConnectionClosed);
                }
            }
        }
        
        // Check max lifetime
        if now.duration_since(self.created_at) > self.max_lifetime {
            self.state = ConnectionState::Closing {
                error_code: 0x0, // NO_ERROR
                reason: "Max lifetime exceeded".to_string(),
                initiated_at: now,
            };
            return Err(QuicError::ConnectionClosed);
        }
        
        Ok(())
    }
    
    /// Start handshake process
    pub fn start_handshake(&mut self) -> QuicResult<()> {
        match self.state {
            ConnectionState::Initial => {
                self.state = ConnectionState::Handshaking;
                self.mark_active();
                Ok(())
            }
            ConnectionState::Handshaking => {
                // Already handshaking, this is fine
                Ok(())
            }
            _ => Err(QuicError::Protocol(format!("Invalid state {:?} for handshake", self.state)))
        }
    }
    
    /// Mark handshake as complete
    pub fn handshake_complete(&mut self) -> QuicResult<()> {
        match self.state {
            ConnectionState::Handshaking => {
                self.state = ConnectionState::Active;
                self.mark_active();
                Ok(())
            }
            ConnectionState::Active => {
                // Already active, this might happen in retransmission scenarios
                Ok(())
            }
            _ => Err(QuicError::Protocol(format!("Invalid state {:?} for handshake completion", self.state)))
        }
    }
    
    /// Initiate connection close
    pub fn close(&mut self, error_code: u64, reason: String) {
        self.state = ConnectionState::Closing {
            error_code,
            reason,
            initiated_at: Instant::now(),
        };
    }
    
    /// Mark connection as fully closed
    pub fn closed(&mut self) {
        self.state = ConnectionState::Closed;
    }
    
    /// Mark connection as failed
    pub fn fail(&mut self, error: String) {
        self.state = ConnectionState::Failed {
            error,
            failed_at: Instant::now(),
        };
    }

    /// Enter draining state (when we receive a close frame)
    pub fn enter_draining(&mut self, error_code: u64, reason: String) {
        self.state = ConnectionState::Draining {
            error_code,
            reason,
            started_at: Instant::now(),
            drain_timeout: self.drain_timeout,
        };
    }

    /// Check if connection is in draining state
    pub fn is_draining(&self) -> bool {
        matches!(self.state, ConnectionState::Draining { .. })
    }

    /// Check if connection is closing or draining
    pub fn is_closing_or_draining(&self) -> bool {
        matches!(self.state, ConnectionState::Closing { .. } | ConnectionState::Draining { .. })
    }
    
    /// Check if connection can send data
    pub fn can_send_data(&self) -> bool {
        matches!(self.state, ConnectionState::Active)
    }
    
    /// Check if connection can receive data
    pub fn can_receive_data(&self) -> bool {
        matches!(self.state, ConnectionState::Active | ConnectionState::Handshaking | ConnectionState::Draining { .. })
    }
    
    /// Check if connection is closed or failed
    pub fn is_closed(&self) -> bool {
        matches!(self.state,
                 ConnectionState::Closed |
                 ConnectionState::Failed { .. })
    }

    /// Check if connection is in any terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(self.state,
                 ConnectionState::Closed |
                 ConnectionState::Failed { .. } |
                 ConnectionState::Closing { .. } |
                 ConnectionState::Draining { .. })
    }
    
    /// Get connection statistics
    pub fn stats(&self) -> ConnectionStateStats {
        let now = Instant::now();
        ConnectionStateStats {
            state: self.state.clone(),
            duration: now.duration_since(self.created_at),
            idle_time: now.duration_since(self.last_activity),
            idle_timeout: self.idle_timeout,
            max_lifetime: self.max_lifetime,
        }
    }
}

#[derive(Debug)]
pub struct ConnectionStateStats {
    pub state: ConnectionState,
    pub duration: Duration,
    pub idle_time: Duration,
    pub idle_timeout: Duration,
    pub max_lifetime: Duration,
}

impl Default for ConnectionStateManager {
    fn default() -> Self {
        Self::new()
    }
}
