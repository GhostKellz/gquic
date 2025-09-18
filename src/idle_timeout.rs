//! QUIC idle timeout management

use std::time::{Duration, Instant};
use crate::{QuicResult, QuicError};
use crate::frame::Frame;

/// Idle timeout manager for QUIC connections
#[derive(Debug, Clone)]
pub struct IdleTimeoutManager {
    /// Base idle timeout from transport parameters
    base_timeout: Duration,
    /// Current effective timeout (may be shorter due to network conditions)
    effective_timeout: Duration,
    /// Maximum allowed idle timeout
    max_timeout: Duration,
    /// Minimum allowed idle timeout
    min_timeout: Duration,
    /// Last time any packet was sent or received
    last_activity: Instant,
    /// Last time we sent a PING frame for keep-alive
    last_ping_sent: Option<Instant>,
    /// Interval for sending keep-alive PINGs
    keepalive_interval: Duration,
    /// Enable adaptive timeout based on network conditions
    adaptive_timeout: bool,
    /// RTT measurements for adaptive timeout
    recent_rtts: Vec<Duration>,
    /// Maximum number of RTT samples to keep
    max_rtt_samples: usize,
}

impl IdleTimeoutManager {
    /// Create a new idle timeout manager
    pub fn new(base_timeout: Duration) -> Self {
        let min_timeout = Duration::from_secs(5);  // RFC minimum
        let max_timeout = Duration::from_secs(600); // 10 minutes max

        Self {
            base_timeout,
            effective_timeout: base_timeout.min(max_timeout).max(min_timeout),
            max_timeout,
            min_timeout,
            last_activity: Instant::now(),
            last_ping_sent: None,
            keepalive_interval: base_timeout / 2, // Send PING at half timeout
            adaptive_timeout: true,
            recent_rtts: Vec::new(),
            max_rtt_samples: 10,
        }
    }

    /// Create with custom parameters
    pub fn with_params(
        base_timeout: Duration,
        min_timeout: Duration,
        max_timeout: Duration,
        adaptive: bool,
    ) -> Self {
        Self {
            base_timeout,
            effective_timeout: base_timeout.min(max_timeout).max(min_timeout),
            max_timeout,
            min_timeout,
            last_activity: Instant::now(),
            last_ping_sent: None,
            keepalive_interval: base_timeout / 2,
            adaptive_timeout: adaptive,
            recent_rtts: Vec::new(),
            max_rtt_samples: 10,
        }
    }

    /// Update last activity timestamp
    pub fn mark_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Check if connection has been idle too long
    pub fn check_idle_timeout(&self) -> QuicResult<()> {
        let now = Instant::now();
        let idle_duration = now.duration_since(self.last_activity);

        if idle_duration > self.effective_timeout {
            Err(QuicError::IdleTimeout)
        } else {
            Ok(())
        }
    }

    /// Check if we should send a keep-alive PING
    pub fn should_send_keepalive(&mut self) -> bool {
        let now = Instant::now();
        let idle_duration = now.duration_since(self.last_activity);

        // Send PING if we've been idle for more than half the timeout
        if idle_duration > self.keepalive_interval {
            // Don't send too frequently
            if let Some(last_ping) = self.last_ping_sent {
                if now.duration_since(last_ping) < Duration::from_secs(1) {
                    return false;
                }
            }

            self.last_ping_sent = Some(now);
            true
        } else {
            false
        }
    }

    /// Create a PING frame for keep-alive
    pub fn create_keepalive_frame(&self) -> Frame {
        Frame::Ping
    }

    /// Add RTT measurement for adaptive timeout
    pub fn add_rtt_measurement(&mut self, rtt: Duration) {
        if !self.adaptive_timeout {
            return;
        }

        self.recent_rtts.push(rtt);
        if self.recent_rtts.len() > self.max_rtt_samples {
            self.recent_rtts.remove(0);
        }

        self.update_adaptive_timeout();
    }

    /// Update timeout based on network conditions
    fn update_adaptive_timeout(&mut self) {
        if self.recent_rtts.is_empty() {
            return;
        }

        // Calculate average RTT
        let avg_rtt = self.recent_rtts.iter().sum::<Duration>() / self.recent_rtts.len() as u32;

        // Adjust timeout based on RTT: more tolerance for high-latency networks
        let rtt_factor = if avg_rtt > Duration::from_millis(200) {
            2.0 // High latency network, be more tolerant
        } else if avg_rtt > Duration::from_millis(50) {
            1.5 // Medium latency
        } else {
            1.0 // Low latency, use base timeout
        };

        let adjusted_timeout = Duration::from_secs_f64(
            self.base_timeout.as_secs_f64() * rtt_factor
        );

        self.effective_timeout = adjusted_timeout
            .min(self.max_timeout)
            .max(self.min_timeout);

        // Update keepalive interval
        self.keepalive_interval = self.effective_timeout / 2;
    }

    /// Get current effective timeout
    pub fn effective_timeout(&self) -> Duration {
        self.effective_timeout
    }

    /// Get time until timeout
    pub fn time_until_timeout(&self) -> Duration {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_activity);

        if elapsed >= self.effective_timeout {
            Duration::ZERO
        } else {
            self.effective_timeout - elapsed
        }
    }

    /// Get idle duration
    pub fn idle_duration(&self) -> Duration {
        Instant::now().duration_since(self.last_activity)
    }

    /// Reset timeout (typically called when transport parameters change)
    pub fn reset_timeout(&mut self, new_timeout: Duration) {
        self.base_timeout = new_timeout;
        self.effective_timeout = new_timeout
            .min(self.max_timeout)
            .max(self.min_timeout);
        self.keepalive_interval = self.effective_timeout / 2;
        self.last_activity = Instant::now();
    }

    /// Enable or disable adaptive timeout
    pub fn set_adaptive(&mut self, adaptive: bool) {
        self.adaptive_timeout = adaptive;
        if !adaptive {
            self.effective_timeout = self.base_timeout
                .min(self.max_timeout)
                .max(self.min_timeout);
            self.keepalive_interval = self.effective_timeout / 2;
        }
    }

    /// Get timeout statistics
    pub fn stats(&self) -> IdleTimeoutStats {
        IdleTimeoutStats {
            base_timeout: self.base_timeout,
            effective_timeout: self.effective_timeout,
            idle_duration: self.idle_duration(),
            time_until_timeout: self.time_until_timeout(),
            keepalive_interval: self.keepalive_interval,
            adaptive_enabled: self.adaptive_timeout,
            avg_rtt: if self.recent_rtts.is_empty() {
                None
            } else {
                Some(self.recent_rtts.iter().sum::<Duration>() / self.recent_rtts.len() as u32)
            },
        }
    }
}

/// Statistics for idle timeout management
#[derive(Debug, Clone)]
pub struct IdleTimeoutStats {
    pub base_timeout: Duration,
    pub effective_timeout: Duration,
    pub idle_duration: Duration,
    pub time_until_timeout: Duration,
    pub keepalive_interval: Duration,
    pub adaptive_enabled: bool,
    pub avg_rtt: Option<Duration>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_idle_timeout_creation() {
        let timeout_mgr = IdleTimeoutManager::new(Duration::from_secs(30));
        assert_eq!(timeout_mgr.effective_timeout(), Duration::from_secs(30));
    }

    #[test]
    fn test_keepalive_interval() {
        let timeout_mgr = IdleTimeoutManager::new(Duration::from_secs(60));
        assert_eq!(timeout_mgr.keepalive_interval, Duration::from_secs(30));
    }

    #[test]
    fn test_adaptive_timeout() {
        let mut timeout_mgr = IdleTimeoutManager::new(Duration::from_secs(30));

        // Add high RTT measurements
        timeout_mgr.add_rtt_measurement(Duration::from_millis(300));
        timeout_mgr.add_rtt_measurement(Duration::from_millis(350));

        // Timeout should be increased for high-latency network
        assert!(timeout_mgr.effective_timeout() > Duration::from_secs(30));
    }
}