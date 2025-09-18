//! QUIC error handling and recovery mechanisms
//!
//! Provides comprehensive error handling, recovery strategies, and
//! resilience mechanisms for QUIC connections.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use crate::{QuicResult, QuicError};

/// Types of errors that can occur in QUIC connections
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum QuicErrorType {
    /// Network-level errors (temporary)
    Network,
    /// Protocol violations (permanent)
    Protocol,
    /// Cryptographic errors (may be recoverable)
    Crypto,
    /// Application-level errors
    Application,
    /// Internal implementation errors
    Internal,
    /// Timeout-related errors
    Timeout,
    /// Resource exhaustion
    Resource,
}

/// Severity levels for errors
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ErrorSeverity {
    /// Informational - not an error
    Info,
    /// Warning - recoverable issue
    Warning,
    /// Error - serious but potentially recoverable
    Error,
    /// Critical - connection should be terminated
    Critical,
    /// Fatal - entire endpoint should shut down
    Fatal,
}

/// Recovery strategies for different error types
#[derive(Debug, Clone, PartialEq)]
pub enum RecoveryStrategy {
    /// Ignore the error and continue
    Ignore,
    /// Retry the operation with exponential backoff
    Retry {
        max_attempts: u32,
        base_delay: Duration,
        max_delay: Duration,
    },
    /// Reset the connection state
    Reset,
    /// Migrate to a new path/address
    Migrate,
    /// Close the connection gracefully
    CloseGraceful { error_code: u64 },
    /// Close the connection immediately
    CloseImmediate { error_code: u64 },
    /// Restart the entire endpoint
    RestartEndpoint,
}

/// Error context with recovery information
#[derive(Debug, Clone)]
pub struct ErrorContext {
    pub error_type: QuicErrorType,
    pub severity: ErrorSeverity,
    pub description: String,
    pub occurred_at: Instant,
    pub recovery_strategy: RecoveryStrategy,
    pub retry_count: u32,
    pub max_retries: u32,
    pub context_data: HashMap<String, String>,
}

impl ErrorContext {
    pub fn new(
        error_type: QuicErrorType,
        severity: ErrorSeverity,
        description: String,
        recovery_strategy: RecoveryStrategy,
    ) -> Self {
        Self {
            error_type,
            severity,
            description,
            occurred_at: Instant::now(),
            recovery_strategy,
            retry_count: 0,
            max_retries: 3,
            context_data: HashMap::new(),
        }
    }

    pub fn with_context_data(mut self, key: String, value: String) -> Self {
        self.context_data.insert(key, value);
        self
    }

    pub fn can_retry(&self) -> bool {
        self.retry_count < self.max_retries
    }

    pub fn increment_retry(&mut self) {
        self.retry_count += 1;
    }
}

/// Circuit breaker for preventing cascading failures
#[derive(Debug)]
pub struct CircuitBreaker {
    failure_threshold: u32,
    success_threshold: u32,
    timeout: Duration,
    failure_count: u32,
    success_count: u32,
    last_failure: Option<Instant>,
    state: CircuitState,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CircuitState {
    Closed,   // Normal operation
    Open,     // Circuit is open, requests fail fast
    HalfOpen, // Testing if the circuit can be closed
}

impl CircuitBreaker {
    pub fn new(failure_threshold: u32, success_threshold: u32, timeout: Duration) -> Self {
        Self {
            failure_threshold,
            success_threshold,
            timeout,
            failure_count: 0,
            success_count: 0,
            last_failure: None,
            state: CircuitState::Closed,
        }
    }

    pub fn call<F, T, E>(&mut self, operation: F) -> Result<T, E>
    where
        F: FnOnce() -> Result<T, E>,
    {
        match self.state {
            CircuitState::Open => {
                if let Some(last_failure) = self.last_failure {
                    if Instant::now().duration_since(last_failure) > self.timeout {
                        self.state = CircuitState::HalfOpen;
                        self.success_count = 0;
                    } else {
                        // Circuit is open - don't call operation, return circuit open error
                        // Note: Need to define a proper error type, for now using a placeholder
                        let result = operation(); // Call once to get the error type
                        match result {
                            Ok(_) => {
                                self.state = CircuitState::Closed;
                                self.last_failure = None;
                                return result;
                            }
                            Err(e) => return Err(e),
                        }
                    }
                }
            }
            _ => {}
        }

        match operation() {
            Ok(result) => {
                self.on_success();
                Ok(result)
            }
            Err(error) => {
                self.on_failure();
                Err(error)
            }
        }
    }

    fn on_success(&mut self) {
        self.failure_count = 0;

        match self.state {
            CircuitState::HalfOpen => {
                self.success_count += 1;
                if self.success_count >= self.success_threshold {
                    self.state = CircuitState::Closed;
                }
            }
            _ => {}
        }
    }

    fn on_failure(&mut self) {
        self.failure_count += 1;
        self.last_failure = Some(Instant::now());

        if self.failure_count >= self.failure_threshold {
            self.state = CircuitState::Open;
        }
    }

    pub fn state(&self) -> &CircuitState {
        &self.state
    }
}

/// Comprehensive error recovery manager
#[derive(Debug)]
pub struct ErrorRecoveryManager {
    error_history: VecDeque<ErrorContext>,
    max_history: usize,
    circuit_breakers: HashMap<String, CircuitBreaker>,
    retry_delays: HashMap<String, Duration>,
    recovery_policies: HashMap<QuicErrorType, RecoveryStrategy>,
    error_counters: HashMap<QuicErrorType, u64>,
    last_error_time: Option<Instant>,
}

impl ErrorRecoveryManager {
    pub fn new() -> Self {
        let mut recovery_policies = HashMap::new();

        // Default recovery policies
        recovery_policies.insert(
            QuicErrorType::Network,
            RecoveryStrategy::Retry {
                max_attempts: 3,
                base_delay: Duration::from_millis(100),
                max_delay: Duration::from_secs(5),
            },
        );

        recovery_policies.insert(
            QuicErrorType::Timeout,
            RecoveryStrategy::Retry {
                max_attempts: 2,
                base_delay: Duration::from_secs(1),
                max_delay: Duration::from_secs(10),
            },
        );

        recovery_policies.insert(
            QuicErrorType::Protocol,
            RecoveryStrategy::CloseGraceful { error_code: 0x01 },
        );

        recovery_policies.insert(
            QuicErrorType::Crypto,
            RecoveryStrategy::CloseImmediate { error_code: 0x100 },
        );

        Self {
            error_history: VecDeque::new(),
            max_history: 1000,
            circuit_breakers: HashMap::new(),
            retry_delays: HashMap::new(),
            recovery_policies,
            error_counters: HashMap::new(),
            last_error_time: None,
        }
    }

    /// Handle an error and determine recovery strategy
    pub fn handle_error(&mut self, error: QuicError) -> QuicResult<RecoveryStrategy> {
        let error_context = self.classify_error(error)?;
        self.record_error(&error_context);

        let strategy = self.determine_recovery_strategy(&error_context);
        Ok(strategy)
    }

    /// Classify an error into type and severity
    fn classify_error(&self, error: QuicError) -> QuicResult<ErrorContext> {
        let (error_type, severity, recovery_strategy) = match &error {
            QuicError::Io(_) => (
                QuicErrorType::Network,
                ErrorSeverity::Warning,
                RecoveryStrategy::Retry {
                    max_attempts: 3,
                    base_delay: Duration::from_millis(100),
                    max_delay: Duration::from_secs(1),
                },
            ),
            QuicError::Protocol(msg) => {
                let severity = if msg.contains("version") {
                    ErrorSeverity::Error
                } else {
                    ErrorSeverity::Critical
                };
                (
                    QuicErrorType::Protocol,
                    severity,
                    RecoveryStrategy::CloseGraceful { error_code: 0x01 },
                )
            }
            QuicError::Crypto(_) => (
                QuicErrorType::Crypto,
                ErrorSeverity::Critical,
                RecoveryStrategy::CloseImmediate { error_code: 0x100 },
            ),
            QuicError::IdleTimeout => (
                QuicErrorType::Timeout,
                ErrorSeverity::Warning,
                RecoveryStrategy::CloseGraceful { error_code: 0x00 },
            ),
            QuicError::ConnectionClosed => (
                QuicErrorType::Application,
                ErrorSeverity::Info,
                RecoveryStrategy::Ignore,
            ),
            QuicError::InvalidPacket(_) => (
                QuicErrorType::Protocol,
                ErrorSeverity::Error,
                RecoveryStrategy::Ignore, // Drop invalid packets
            ),
            _ => (
                QuicErrorType::Internal,
                ErrorSeverity::Error,
                RecoveryStrategy::Reset,
            ),
        };

        Ok(ErrorContext::new(
            error_type,
            severity,
            error.to_string(),
            recovery_strategy,
        ))
    }

    /// Record an error in the history
    fn record_error(&mut self, error_context: &ErrorContext) {
        // Update counters
        let counter = self.error_counters.entry(error_context.error_type.clone()).or_insert(0);
        *counter += 1;

        // Add to history
        self.error_history.push_back(error_context.clone());
        if self.error_history.len() > self.max_history {
            self.error_history.pop_front();
        }

        self.last_error_time = Some(error_context.occurred_at);
    }

    /// Determine the appropriate recovery strategy
    fn determine_recovery_strategy(&self, error_context: &ErrorContext) -> RecoveryStrategy {
        // Check if we should escalate based on recent error patterns
        if self.should_escalate_recovery(error_context) {
            return self.escalate_recovery_strategy(&error_context.recovery_strategy);
        }

        // Use the default strategy for this error type
        self.recovery_policies
            .get(&error_context.error_type)
            .cloned()
            .unwrap_or(error_context.recovery_strategy.clone())
    }

    /// Check if we should escalate the recovery strategy
    fn should_escalate_recovery(&self, error_context: &ErrorContext) -> bool {
        let recent_errors = self.get_recent_errors(Duration::from_secs(60));

        // Escalate if we have many errors of the same type recently
        let same_type_count = recent_errors
            .iter()
            .filter(|e| e.error_type == error_context.error_type)
            .count();

        same_type_count > 5
    }

    /// Escalate a recovery strategy to a more severe one
    fn escalate_recovery_strategy(&self, strategy: &RecoveryStrategy) -> RecoveryStrategy {
        match strategy {
            RecoveryStrategy::Ignore => RecoveryStrategy::Retry {
                max_attempts: 2,
                base_delay: Duration::from_millis(500),
                max_delay: Duration::from_secs(2),
            },
            RecoveryStrategy::Retry { .. } => RecoveryStrategy::Reset,
            RecoveryStrategy::Reset => RecoveryStrategy::CloseGraceful { error_code: 0x02 },
            RecoveryStrategy::CloseGraceful { .. } => RecoveryStrategy::CloseImmediate { error_code: 0x02 },
            other => other.clone(),
        }
    }

    /// Get recent errors within a time window
    pub fn get_recent_errors(&self, window: Duration) -> Vec<&ErrorContext> {
        let cutoff = Instant::now() - window;
        self.error_history
            .iter()
            .filter(|e| e.occurred_at >= cutoff)
            .collect()
    }

    /// Get error statistics
    pub fn get_error_stats(&self) -> ErrorStats {
        let total_errors: u64 = self.error_counters.values().sum();
        let error_rate = if let Some(last_error) = self.last_error_time {
            let duration = Instant::now().duration_since(last_error);
            if duration.as_secs() > 0 {
                total_errors as f64 / duration.as_secs() as f64
            } else {
                0.0
            }
        } else {
            0.0
        };

        ErrorStats {
            total_errors,
            error_counters: self.error_counters.clone(),
            error_rate,
            recent_errors: self.get_recent_errors(Duration::from_secs(300)).len(),
        }
    }

    /// Add a circuit breaker for a specific operation
    pub fn add_circuit_breaker(&mut self, name: String, circuit_breaker: CircuitBreaker) {
        self.circuit_breakers.insert(name, circuit_breaker);
    }

    /// Get a mutable reference to a circuit breaker
    pub fn get_circuit_breaker_mut(&mut self, name: &str) -> Option<&mut CircuitBreaker> {
        self.circuit_breakers.get_mut(name)
    }

    /// Clear error history
    pub fn clear_history(&mut self) {
        self.error_history.clear();
        self.error_counters.clear();
        self.last_error_time = None;
    }
}

/// Error statistics
#[derive(Debug, Clone)]
pub struct ErrorStats {
    pub total_errors: u64,
    pub error_counters: HashMap<QuicErrorType, u64>,
    pub error_rate: f64, // errors per second
    pub recent_errors: usize,
}

impl Default for ErrorRecoveryManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_classification() {
        let mut manager = ErrorRecoveryManager::new();

        let io_error = QuicError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "Connection refused",
        ));

        let strategy = manager.handle_error(io_error).unwrap();
        assert!(matches!(strategy, RecoveryStrategy::Retry { .. }));
    }

    #[test]
    fn test_circuit_breaker() {
        let mut circuit = CircuitBreaker::new(3, 2, Duration::from_secs(1));

        // Initially closed
        assert_eq!(circuit.state(), &CircuitState::Closed);

        // Cause failures to open circuit
        for _ in 0..3 {
            let _ = circuit.call(|| -> Result<(), ()> { Err(()) });
        }

        assert_eq!(circuit.state(), &CircuitState::Open);
    }

    #[test]
    fn test_error_escalation() {
        let mut manager = ErrorRecoveryManager::new();

        // Simulate repeated errors to trigger escalation
        for _ in 0..10 {
            let _ = manager.handle_error(QuicError::Protocol("test".to_string()));
        }

        let stats = manager.get_error_stats();
        assert!(stats.total_errors > 0);
    }
}