//! QUIC congestion control implementation
//!
//! This module implements congestion control algorithms for QUIC,
//! starting with NewReno as specified in RFC 9002 Appendix B.

use crate::quic::error::{QuicError, Result};
use crate::protection::PacketNumber;
use crate::recovery::{SentPacket, LossDetectionStats};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Congestion control algorithm trait
pub trait CongestionController: Send + Sync + std::fmt::Debug {
    /// Called when a packet is sent
    fn on_packet_sent(&mut self, sent_time: Instant, packet_number: PacketNumber, bytes: usize, is_retransmission: bool);

    /// Called when packets are acknowledged
    fn on_packets_acked(&mut self, acked_packets: &[SentPacket], rtt_stats: &LossDetectionStats);

    /// Called when packets are lost
    fn on_packets_lost(&mut self, lost_packets: &[SentPacket]);

    /// Called on persistent congestion
    fn on_persistent_congestion(&mut self);

    /// Get current congestion window
    fn congestion_window(&self) -> usize;

    /// Get bytes in flight limit
    fn bytes_in_flight_limit(&self) -> usize;

    /// Check if more data can be sent
    fn can_send(&self, bytes_in_flight: usize) -> bool {
        bytes_in_flight + self.minimum_window() <= self.congestion_window()
    }

    /// Minimum congestion window
    fn minimum_window(&self) -> usize {
        2 * self.max_datagram_size()
    }

    /// Maximum datagram size
    fn max_datagram_size(&self) -> usize;

    /// Get current state for debugging
    fn debug_state(&self) -> CongestionDebugState;
}

/// Debug state for congestion control
#[derive(Debug, Clone)]
pub struct CongestionDebugState {
    pub algorithm: String,
    pub congestion_window: usize,
    pub ssthresh: usize,
    pub bytes_in_flight: usize,
    pub state: String,
}

/// NewReno congestion control implementation
#[derive(Debug)]
pub struct NewReno {
    /// Maximum datagram size
    max_datagram_size: usize,
    /// Current congestion window
    congestion_window: usize,
    /// Slow start threshold
    ssthresh: usize,
    /// Bytes acknowledged in current RTT
    bytes_acked_in_rtt: usize,
    /// End of recovery period packet number
    recovery_start_time: Option<Instant>,
    /// Initial congestion window
    initial_window: usize,
    /// Maximum congestion window
    max_congestion_window: usize,
    /// Minimum congestion window
    min_congestion_window: usize,
    /// Last update time
    last_update: Instant,
}

impl NewReno {
    /// Create a new NewReno congestion controller
    pub fn new(max_datagram_size: usize) -> Self {
        let initial_window = std::cmp::min(
            10 * max_datagram_size,
            std::cmp::max(2 * max_datagram_size, 14720)
        );

        Self {
            max_datagram_size,
            congestion_window: initial_window,
            ssthresh: usize::MAX,
            bytes_acked_in_rtt: 0,
            recovery_start_time: None,
            initial_window,
            max_congestion_window: 16 * 1024 * 1024, // 16MB
            min_congestion_window: 2 * max_datagram_size,
            last_update: Instant::now(),
        }
    }

    /// Check if we're in slow start
    fn in_slow_start(&self) -> bool {
        self.congestion_window < self.ssthresh
    }

    /// Check if we're in recovery
    fn in_recovery(&self, sent_time: Instant) -> bool {
        self.recovery_start_time
            .map(|recovery_start| sent_time <= recovery_start)
            .unwrap_or(false)
    }

    /// Enter recovery period
    fn enter_recovery(&mut self, sent_time: Instant) {
        if self.recovery_start_time.is_none() || sent_time > self.recovery_start_time.unwrap() {
            self.recovery_start_time = Some(sent_time);

            // Reduce congestion window (multiplicative decrease)
            self.ssthresh = std::cmp::max(
                self.congestion_window / 2,
                self.min_congestion_window
            );
            self.congestion_window = self.ssthresh;

            info!("Entered recovery: cwnd={}, ssthresh={}",
                  self.congestion_window, self.ssthresh);
        }
    }

    /// Exit recovery period
    fn exit_recovery(&mut self) {
        self.recovery_start_time = None;
        self.bytes_acked_in_rtt = 0;
        debug!("Exited recovery");
    }

    /// Increase congestion window during slow start
    fn slow_start_increase(&mut self, acked_bytes: usize) {
        self.congestion_window += acked_bytes;
        self.congestion_window = std::cmp::min(
            self.congestion_window,
            self.max_congestion_window
        );

        debug!("Slow start: cwnd increased to {}", self.congestion_window);
    }

    /// Increase congestion window during congestion avoidance
    fn congestion_avoidance_increase(&mut self, acked_bytes: usize) {
        self.bytes_acked_in_rtt += acked_bytes;

        // Increase cwnd by max_datagram_size per RTT
        if self.bytes_acked_in_rtt >= self.congestion_window {
            self.bytes_acked_in_rtt -= self.congestion_window;
            self.congestion_window += self.max_datagram_size;
            self.congestion_window = std::cmp::min(
                self.congestion_window,
                self.max_congestion_window
            );

            debug!("Congestion avoidance: cwnd increased to {}", self.congestion_window);
        }
    }

    /// Reset to initial state
    fn reset(&mut self) {
        self.congestion_window = self.initial_window;
        self.ssthresh = usize::MAX;
        self.bytes_acked_in_rtt = 0;
        self.recovery_start_time = None;

        info!("Congestion control reset: cwnd={}", self.congestion_window);
    }
}

impl CongestionController for NewReno {
    fn on_packet_sent(&mut self, _sent_time: Instant, _packet_number: PacketNumber, _bytes: usize, _is_retransmission: bool) {
        // NewReno doesn't need to track individual sent packets
        self.last_update = Instant::now();
    }

    fn on_packets_acked(&mut self, acked_packets: &[SentPacket], _rtt_stats: &LossDetectionStats) {
        if acked_packets.is_empty() {
            return;
        }

        // Calculate total acked bytes
        let total_acked: usize = acked_packets.iter()
            .map(|p| p.size)
            .sum();

        // Find the latest sent time among acked packets
        let latest_sent_time = acked_packets.iter()
            .map(|p| p.time_sent)
            .max()
            .unwrap_or_else(Instant::now);

        // If we're in recovery and the latest acked packet was sent after
        // recovery started, we can exit recovery
        if self.in_recovery(latest_sent_time) {
            // Still in recovery - don't increase window
            debug!("In recovery - not increasing window");
            return;
        }

        // If we were in recovery but latest packet was sent after recovery,
        // we can now exit recovery
        if self.recovery_start_time.is_some() {
            self.exit_recovery();
        }

        // Increase congestion window based on current state
        if self.in_slow_start() {
            self.slow_start_increase(total_acked);

            // Check if we should exit slow start
            if self.congestion_window >= self.ssthresh {
                debug!("Exiting slow start at cwnd={}", self.congestion_window);
            }
        } else {
            self.congestion_avoidance_increase(total_acked);
        }

        debug!("Acked {} bytes, cwnd={}, ssthresh={}, in_ss={}",
               total_acked, self.congestion_window, self.ssthresh, self.in_slow_start());
    }

    fn on_packets_lost(&mut self, lost_packets: &[SentPacket]) {
        if lost_packets.is_empty() {
            return;
        }

        // Find the latest sent time among lost packets
        let latest_sent_time = lost_packets.iter()
            .map(|p| p.time_sent)
            .max()
            .unwrap_or_else(Instant::now);

        // Only react to loss if packet was sent outside current recovery period
        if !self.in_recovery(latest_sent_time) {
            self.enter_recovery(latest_sent_time);
        }

        let total_lost: usize = lost_packets.iter()
            .map(|p| p.size)
            .sum();

        warn!("Lost {} bytes in {} packets", total_lost, lost_packets.len());
    }

    fn on_persistent_congestion(&mut self) {
        warn!("Persistent congestion detected - resetting congestion control");
        self.reset();
    }

    fn congestion_window(&self) -> usize {
        self.congestion_window
    }

    fn bytes_in_flight_limit(&self) -> usize {
        self.congestion_window
    }

    fn max_datagram_size(&self) -> usize {
        self.max_datagram_size
    }

    fn debug_state(&self) -> CongestionDebugState {
        let state = if self.recovery_start_time.is_some() {
            "Recovery".to_string()
        } else if self.in_slow_start() {
            "SlowStart".to_string()
        } else {
            "CongestionAvoidance".to_string()
        };

        CongestionDebugState {
            algorithm: "NewReno".to_string(),
            congestion_window: self.congestion_window,
            ssthresh: self.ssthresh,
            bytes_in_flight: 0, // This would be tracked by the caller
            state,
        }
    }
}

/// Cubic congestion control (placeholder for future implementation)
#[derive(Debug)]
pub struct Cubic {
    newreno: NewReno,
    // Cubic-specific fields would go here
}

impl Cubic {
    pub fn new(max_datagram_size: usize) -> Self {
        Self {
            newreno: NewReno::new(max_datagram_size),
        }
    }
}

impl CongestionController for Cubic {
    fn on_packet_sent(&mut self, sent_time: Instant, packet_number: PacketNumber, bytes: usize, is_retransmission: bool) {
        // For now, delegate to NewReno
        self.newreno.on_packet_sent(sent_time, packet_number, bytes, is_retransmission);
    }

    fn on_packets_acked(&mut self, acked_packets: &[SentPacket], rtt_stats: &LossDetectionStats) {
        // For now, delegate to NewReno
        self.newreno.on_packets_acked(acked_packets, rtt_stats);
    }

    fn on_packets_lost(&mut self, lost_packets: &[SentPacket]) {
        // For now, delegate to NewReno
        self.newreno.on_packets_lost(lost_packets);
    }

    fn on_persistent_congestion(&mut self) {
        self.newreno.on_persistent_congestion();
    }

    fn congestion_window(&self) -> usize {
        self.newreno.congestion_window()
    }

    fn bytes_in_flight_limit(&self) -> usize {
        self.newreno.bytes_in_flight_limit()
    }

    fn max_datagram_size(&self) -> usize {
        self.newreno.max_datagram_size()
    }

    fn debug_state(&self) -> CongestionDebugState {
        let mut state = self.newreno.debug_state();
        state.algorithm = "Cubic".to_string();
        state
    }
}

/// BBR congestion control (placeholder for future implementation)
#[derive(Debug)]
pub struct Bbr {
    newreno: NewReno,
    // BBR-specific fields would go here
}

impl Bbr {
    pub fn new(max_datagram_size: usize) -> Self {
        Self {
            newreno: NewReno::new(max_datagram_size),
        }
    }
}

impl CongestionController for Bbr {
    fn on_packet_sent(&mut self, sent_time: Instant, packet_number: PacketNumber, bytes: usize, is_retransmission: bool) {
        self.newreno.on_packet_sent(sent_time, packet_number, bytes, is_retransmission);
    }

    fn on_packets_acked(&mut self, acked_packets: &[SentPacket], rtt_stats: &LossDetectionStats) {
        self.newreno.on_packets_acked(acked_packets, rtt_stats);
    }

    fn on_packets_lost(&mut self, lost_packets: &[SentPacket]) {
        self.newreno.on_packets_lost(lost_packets);
    }

    fn on_persistent_congestion(&mut self) {
        self.newreno.on_persistent_congestion();
    }

    fn congestion_window(&self) -> usize {
        self.newreno.congestion_window()
    }

    fn bytes_in_flight_limit(&self) -> usize {
        self.newreno.bytes_in_flight_limit()
    }

    fn max_datagram_size(&self) -> usize {
        self.newreno.max_datagram_size()
    }

    fn debug_state(&self) -> CongestionDebugState {
        let mut state = self.newreno.debug_state();
        state.algorithm = "BBR".to_string();
        state
    }
}

/// Congestion control configuration
#[derive(Debug, Clone)]
pub struct CongestionControlConfig {
    /// Algorithm to use
    pub algorithm: CongestionAlgorithm,
    /// Maximum datagram size
    pub max_datagram_size: usize,
    /// Initial congestion window multiplier
    pub initial_window_multiplier: f64,
    /// Maximum congestion window
    pub max_congestion_window: usize,
}

/// Available congestion control algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionAlgorithm {
    NewReno,
    Cubic,
    Bbr,
}

impl Default for CongestionControlConfig {
    fn default() -> Self {
        Self {
            algorithm: CongestionAlgorithm::NewReno,
            max_datagram_size: 1200,
            initial_window_multiplier: 1.0,
            max_congestion_window: 16 * 1024 * 1024, // 16MB
        }
    }
}

/// Create a congestion controller
pub fn create_congestion_controller(config: &CongestionControlConfig) -> Box<dyn CongestionController> {
    match config.algorithm {
        CongestionAlgorithm::NewReno => Box::new(NewReno::new(config.max_datagram_size)),
        CongestionAlgorithm::Cubic => Box::new(Cubic::new(config.max_datagram_size)),
        CongestionAlgorithm::Bbr => Box::new(Bbr::new(config.max_datagram_size)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_newreno_slow_start() {
        let mut newreno = NewReno::new(1200);
        let initial_cwnd = newreno.congestion_window();

        // Create a mock acked packet
        let packet = SentPacket {
            packet_number: PacketNumber(1),
            time_sent: Instant::now(),
            size: 1200,
            ack_eliciting: true,
            in_flight: true,
            level: crate::tls::EncryptionLevel::Application,
            data: bytes::Bytes::new(),
            is_probe: false,
        };

        let stats = LossDetectionStats {
            smoothed_rtt: Duration::from_millis(100),
            rtt_var: Duration::from_millis(50),
            min_rtt: Duration::from_millis(80),
            bytes_in_flight: 1200,
            pto_count: 0,
            lost_packets: 0,
        };

        // In slow start, cwnd should increase by acked bytes
        newreno.on_packets_acked(&[packet], &stats);
        assert!(newreno.congestion_window() > initial_cwnd);
        assert!(newreno.in_slow_start());
    }

    #[test]
    fn test_newreno_loss_response() {
        let mut newreno = NewReno::new(1200);

        // Set a larger congestion window
        newreno.congestion_window = 12000;
        newreno.ssthresh = usize::MAX;

        let lost_packet = SentPacket {
            packet_number: PacketNumber(1),
            time_sent: Instant::now(),
            size: 1200,
            ack_eliciting: true,
            in_flight: true,
            level: crate::tls::EncryptionLevel::Application,
            data: bytes::Bytes::new(),
            is_probe: false,
        };

        let initial_cwnd = newreno.congestion_window();
        newreno.on_packets_lost(&[lost_packet]);

        // Should reduce congestion window
        assert!(newreno.congestion_window() < initial_cwnd);
        assert!(!newreno.in_slow_start());
    }

    #[test]
    fn test_persistent_congestion() {
        let mut newreno = NewReno::new(1200);
        newreno.congestion_window = 12000;

        newreno.on_persistent_congestion();

        // Should reset to initial window
        assert_eq!(newreno.congestion_window(), newreno.initial_window);
        assert!(newreno.in_slow_start());
    }
}