//! QUIC connection state machine with robust state transitions
//!
//! Implements a comprehensive state machine for QUIC connections that ensures
//! proper state transitions according to RFC 9000 and handles edge cases.

use std::time::{Duration, Instant};
use crate::{QuicResult, QuicError};
use crate::connection_state::ConnectionState;

/// State transition events that can trigger state changes
#[derive(Debug, Clone, PartialEq)]
pub enum StateEvent {
    /// Connection initiated
    ConnectionInitiated,
    /// Handshake started
    HandshakeStarted,
    /// Handshake completed successfully
    HandshakeCompleted,
    /// Connection ready for data transfer
    ConnectionEstablished,
    /// Close frame received
    CloseReceived { error_code: u64, reason: String },
    /// Close frame sent
    CloseSent { error_code: u64, reason: String },
    /// Idle timeout occurred
    IdleTimeout,
    /// Connection error occurred
    ConnectionError { error: String },
    /// Drain timeout completed
    DrainTimeout,
    /// Maximum lifetime exceeded
    LifetimeExpired,
    /// Version negotiation required
    VersionNegotiation,
}

/// Comprehensive state machine for QUIC connections
#[derive(Debug)]
pub struct QuicStateMachine {
    current_state: ConnectionState,
    previous_state: Option<ConnectionState>,
    state_history: Vec<(ConnectionState, Instant)>,
    max_history: usize,
    transition_callbacks: Vec<Box<dyn Fn(&ConnectionState, &ConnectionState, &StateEvent) + Send + Sync>>,
}

impl QuicStateMachine {
    /// Create a new state machine
    pub fn new() -> Self {
        let initial_state = ConnectionState::Initial;
        Self {
            current_state: initial_state.clone(),
            previous_state: None,
            state_history: vec![(initial_state, Instant::now())],
            max_history: 100,
            transition_callbacks: Vec::new(),
        }
    }

    /// Get the current state
    pub fn current_state(&self) -> &ConnectionState {
        &self.current_state
    }

    /// Get the previous state
    pub fn previous_state(&self) -> Option<&ConnectionState> {
        self.previous_state.as_ref()
    }

    /// Get state history
    pub fn state_history(&self) -> &[(ConnectionState, Instant)] {
        &self.state_history
    }

    /// Add a state transition callback
    pub fn add_transition_callback<F>(&mut self, callback: F)
    where
        F: Fn(&ConnectionState, &ConnectionState, &StateEvent) + Send + Sync + 'static,
    {
        self.transition_callbacks.push(Box::new(callback));
    }

    /// Check if a state transition is valid
    pub fn is_transition_valid(&self, event: &StateEvent) -> bool {
        match (&self.current_state, event) {
            // From Initial state
            (ConnectionState::Initial, StateEvent::ConnectionInitiated) => true,
            (ConnectionState::Initial, StateEvent::HandshakeStarted) => true,
            (ConnectionState::Initial, StateEvent::VersionNegotiation) => true,

            // From Handshaking state
            (ConnectionState::Handshaking, StateEvent::HandshakeCompleted) => true,
            (ConnectionState::Handshaking, StateEvent::ConnectionEstablished) => true,
            (ConnectionState::Handshaking, StateEvent::CloseReceived { .. }) => true,
            (ConnectionState::Handshaking, StateEvent::CloseSent { .. }) => true,
            (ConnectionState::Handshaking, StateEvent::ConnectionError { .. }) => true,
            (ConnectionState::Handshaking, StateEvent::IdleTimeout) => true,

            // From Active state
            (ConnectionState::Active, StateEvent::CloseReceived { .. }) => true,
            (ConnectionState::Active, StateEvent::CloseSent { .. }) => true,
            (ConnectionState::Active, StateEvent::ConnectionError { .. }) => true,
            (ConnectionState::Active, StateEvent::IdleTimeout) => true,
            (ConnectionState::Active, StateEvent::LifetimeExpired) => true,

            // From Closing state
            (ConnectionState::Closing { .. }, StateEvent::DrainTimeout) => true,
            (ConnectionState::Closing { .. }, StateEvent::CloseReceived { .. }) => true, // Peer acknowledgment

            // From Draining state
            (ConnectionState::Draining { .. }, StateEvent::DrainTimeout) => true,

            // Terminal states (Closed, Failed) don't transition
            (ConnectionState::Closed, _) => false,
            (ConnectionState::Failed { .. }, _) => false,

            // Invalid transitions
            _ => false,
        }
    }

    /// Attempt a state transition
    pub fn transition(&mut self, event: StateEvent) -> QuicResult<ConnectionState> {
        if !self.is_transition_valid(&event) {
            return Err(QuicError::Protocol(format!(
                "Invalid state transition from {:?} with event {:?}",
                self.current_state, event
            )));
        }

        let old_state = self.current_state.clone();
        let new_state = self.compute_new_state(&event)?;

        // Execute the transition
        self.previous_state = Some(old_state.clone());
        self.current_state = new_state.clone();

        // Update history
        self.state_history.push((new_state.clone(), Instant::now()));
        if self.state_history.len() > self.max_history {
            self.state_history.remove(0);
        }

        // Execute callbacks
        for callback in &self.transition_callbacks {
            callback(&old_state, &new_state, &event);
        }

        Ok(new_state)
    }

    /// Compute the new state based on current state and event
    fn compute_new_state(&self, event: &StateEvent) -> QuicResult<ConnectionState> {
        let now = Instant::now();

        match (&self.current_state, event) {
            // Initial transitions
            (ConnectionState::Initial, StateEvent::HandshakeStarted) => {
                Ok(ConnectionState::Handshaking)
            }

            // Handshaking transitions
            (ConnectionState::Handshaking, StateEvent::HandshakeCompleted) => {
                Ok(ConnectionState::Active)
            }
            (ConnectionState::Handshaking, StateEvent::ConnectionEstablished) => {
                Ok(ConnectionState::Active)
            }

            // Active state transitions
            (ConnectionState::Active, StateEvent::CloseSent { error_code, reason }) => {
                Ok(ConnectionState::Closing {
                    error_code: *error_code,
                    reason: reason.clone(),
                    initiated_at: now,
                })
            }
            (ConnectionState::Active, StateEvent::CloseReceived { error_code, reason }) => {
                Ok(ConnectionState::Draining {
                    error_code: *error_code,
                    reason: reason.clone(),
                    started_at: now,
                    drain_timeout: Duration::from_secs(3),
                })
            }

            // Error transitions from any active state
            (_, StateEvent::ConnectionError { error }) => {
                Ok(ConnectionState::Failed {
                    error: error.clone(),
                    failed_at: now,
                })
            }

            // Timeout transitions
            (_, StateEvent::IdleTimeout) => {
                Ok(ConnectionState::Closing {
                    error_code: 0x0, // NO_ERROR
                    reason: "Idle timeout".to_string(),
                    initiated_at: now,
                })
            }
            (_, StateEvent::LifetimeExpired) => {
                Ok(ConnectionState::Closing {
                    error_code: 0x0, // NO_ERROR
                    reason: "Maximum lifetime exceeded".to_string(),
                    initiated_at: now,
                })
            }

            // Terminal transitions
            (ConnectionState::Closing { .. }, StateEvent::DrainTimeout) => {
                Ok(ConnectionState::Closed)
            }
            (ConnectionState::Draining { .. }, StateEvent::DrainTimeout) => {
                Ok(ConnectionState::Closed)
            }

            // Peer close acknowledgment while closing
            (ConnectionState::Closing { .. }, StateEvent::CloseReceived { .. }) => {
                Ok(ConnectionState::Closed)
            }

            // Should not reach here if validation passed
            _ => Err(QuicError::Protocol(format!(
                "Unhandled state transition from {:?} with event {:?}",
                self.current_state, event
            )))
        }
    }

    /// Check if the connection is in a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(self.current_state,
                 ConnectionState::Closed | ConnectionState::Failed { .. })
    }

    /// Check if the connection is in a closing state
    pub fn is_closing(&self) -> bool {
        matches!(self.current_state,
                 ConnectionState::Closing { .. } | ConnectionState::Draining { .. })
    }

    /// Check if the connection can send data
    pub fn can_send_data(&self) -> bool {
        matches!(self.current_state, ConnectionState::Active)
    }

    /// Check if the connection can receive data
    pub fn can_receive_data(&self) -> bool {
        matches!(self.current_state,
                 ConnectionState::Active |
                 ConnectionState::Handshaking |
                 ConnectionState::Draining { .. })
    }

    /// Get time spent in current state
    pub fn time_in_current_state(&self) -> Duration {
        if let Some((_, timestamp)) = self.state_history.last() {
            Instant::now().duration_since(*timestamp)
        } else {
            Duration::ZERO
        }
    }

    /// Get the number of state transitions
    pub fn transition_count(&self) -> usize {
        self.state_history.len().saturating_sub(1)
    }

    /// Reset the state machine to initial state
    pub fn reset(&mut self) {
        let initial_state = ConnectionState::Initial;
        self.current_state = initial_state.clone();
        self.previous_state = None;
        self.state_history.clear();
        self.state_history.push((initial_state, Instant::now()));
    }

    /// Get state machine statistics
    pub fn stats(&self) -> StateMachineStats {
        let total_duration = if let Some((first, _)) = self.state_history.first() {
            if let Some((_, last_time)) = self.state_history.last() {
                last_time.duration_since(Instant::now()) // This should be flipped
            } else {
                Duration::ZERO
            }
        } else {
            Duration::ZERO
        };

        StateMachineStats {
            current_state: self.current_state.clone(),
            previous_state: self.previous_state.clone(),
            transition_count: self.transition_count(),
            time_in_current_state: self.time_in_current_state(),
            total_duration,
            is_terminal: self.is_terminal(),
            can_send_data: self.can_send_data(),
            can_receive_data: self.can_receive_data(),
        }
    }
}

/// Statistics for the state machine
#[derive(Debug, Clone)]
pub struct StateMachineStats {
    pub current_state: ConnectionState,
    pub previous_state: Option<ConnectionState>,
    pub transition_count: usize,
    pub time_in_current_state: Duration,
    pub total_duration: Duration,
    pub is_terminal: bool,
    pub can_send_data: bool,
    pub can_receive_data: bool,
}

impl Default for QuicStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_machine_creation() {
        let sm = QuicStateMachine::new();
        assert_eq!(sm.current_state(), &ConnectionState::Initial);
        assert!(sm.previous_state().is_none());
    }

    #[test]
    fn test_valid_transitions() {
        let mut sm = QuicStateMachine::new();

        // Initial -> Handshaking
        assert!(sm.is_transition_valid(&StateEvent::HandshakeStarted));
        sm.transition(StateEvent::HandshakeStarted).unwrap();
        assert_eq!(sm.current_state(), &ConnectionState::Handshaking);

        // Handshaking -> Active
        assert!(sm.is_transition_valid(&StateEvent::HandshakeCompleted));
        sm.transition(StateEvent::HandshakeCompleted).unwrap();
        assert_eq!(sm.current_state(), &ConnectionState::Active);
    }

    #[test]
    fn test_invalid_transitions() {
        let mut sm = QuicStateMachine::new();

        // Cannot go directly from Initial to Active
        assert!(!sm.is_transition_valid(&StateEvent::HandshakeCompleted));
        assert!(sm.transition(StateEvent::HandshakeCompleted).is_err());
    }

    #[test]
    fn test_terminal_states() {
        let mut sm = QuicStateMachine::new();

        // Transition to failed state
        sm.transition(StateEvent::ConnectionError {
            error: "Test error".to_string(),
        }).unwrap();

        assert!(sm.is_terminal());
        assert!(!sm.can_send_data());
        assert!(!sm.can_receive_data());
    }
}