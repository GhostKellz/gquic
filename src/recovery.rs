//! QUIC loss detection and recovery implementation
//!
//! This module implements loss detection, acknowledgment processing,
//! and packet retransmission as specified in RFC 9002.

use crate::quic::error::{QuicError, Result};
use crate::protection::PacketNumber;
use crate::tls::EncryptionLevel;
use bytes::Bytes;
use std::collections::{HashMap, VecDeque, BTreeMap};
use std::time::{Duration, Instant};
use tracing::{debug, warn};

/// Configuration for loss detection
#[derive(Debug, Clone)]
pub struct LossDetectionConfig {
    /// Initial RTT estimate
    pub initial_rtt: Duration,
    /// Maximum acknowledgment delay
    pub max_ack_delay: Duration,
    /// Time threshold for loss detection (fraction of RTT)
    pub time_threshold: f64,
    /// Packet threshold for loss detection
    pub packet_threshold: u64,
    /// Persistent congestion duration threshold
    pub persistent_congestion_threshold: Duration,
    /// Probe timeout (PTO) base
    pub pto_base: Duration,
    /// Maximum PTO duration
    pub max_pto: Duration,
}

impl Default for LossDetectionConfig {
    fn default() -> Self {
        Self {
            initial_rtt: Duration::from_millis(500),
            max_ack_delay: Duration::from_millis(25),
            time_threshold: 9.0 / 8.0,  // 1.125
            packet_threshold: 3,
            persistent_congestion_threshold: Duration::from_secs(1),
            pto_base: Duration::from_millis(1),
            max_pto: Duration::from_secs(60),
        }
    }
}

/// RTT statistics
#[derive(Debug, Clone)]
pub struct RttStats {
    /// Smoothed RTT
    pub smoothed_rtt: Duration,
    /// RTT variation
    pub rtt_var: Duration,
    /// Minimum RTT observed
    pub min_rtt: Duration,
    /// Latest RTT sample
    pub latest_rtt: Duration,
}

impl RttStats {
    pub fn new(initial_rtt: Duration) -> Self {
        Self {
            smoothed_rtt: initial_rtt,
            rtt_var: initial_rtt / 2,
            min_rtt: Duration::MAX,
            latest_rtt: Duration::ZERO,
        }
    }

    /// Update RTT statistics with a new sample
    pub fn update(&mut self, rtt_sample: Duration, ack_delay: Duration) {
        self.latest_rtt = rtt_sample;

        // Update minimum RTT
        if rtt_sample < self.min_rtt {
            self.min_rtt = rtt_sample;
        }

        // Adjust for acknowledgment delay
        let adjusted_rtt = if self.min_rtt.is_zero() || rtt_sample > self.min_rtt + ack_delay {
            rtt_sample.saturating_sub(ack_delay)
        } else {
            rtt_sample
        };

        // First RTT sample
        if self.smoothed_rtt.is_zero() {
            self.smoothed_rtt = adjusted_rtt;
            self.rtt_var = adjusted_rtt / 2;
        } else {
            // Exponential weighted moving average
            let rtt_var_sample = if self.smoothed_rtt > adjusted_rtt {
                self.smoothed_rtt - adjusted_rtt
            } else {
                adjusted_rtt - self.smoothed_rtt
            };

            self.rtt_var = self.rtt_var * 3 / 4 + rtt_var_sample / 4;
            self.smoothed_rtt = self.smoothed_rtt * 7 / 8 + adjusted_rtt / 8;
        }
    }

    /// Calculate probe timeout (PTO)
    pub fn pto(&self, max_ack_delay: Duration) -> Duration {
        self.smoothed_rtt + 4 * self.rtt_var + max_ack_delay
    }
}

/// Information about a sent packet
#[derive(Debug, Clone)]
pub struct SentPacket {
    /// Packet number
    pub packet_number: PacketNumber,
    /// Time when packet was sent
    pub time_sent: Instant,
    /// Size of the packet
    pub size: usize,
    /// Whether this packet is ack-eliciting
    pub ack_eliciting: bool,
    /// Whether this packet contains crypto data
    pub in_flight: bool,
    /// Encryption level
    pub level: EncryptionLevel,
    /// Packet contents for retransmission
    pub data: Bytes,
    /// Whether this is a probe packet
    pub is_probe: bool,
}

/// Acknowledgment range
#[derive(Debug, Clone)]
pub struct AckRange {
    /// Start of the range (inclusive)
    pub start: PacketNumber,
    /// End of the range (inclusive)
    pub end: PacketNumber,
}

impl AckRange {
    pub fn new(start: PacketNumber, end: PacketNumber) -> Self {
        Self { start, end }
    }

    /// Check if a packet number is in this range
    pub fn contains(&self, packet_number: PacketNumber) -> bool {
        packet_number.value() >= self.start.value() && packet_number.value() <= self.end.value()
    }

    /// Get the size of this range
    pub fn size(&self) -> u64 {
        self.end.value() - self.start.value() + 1
    }
}

/// Loss detection and recovery state
#[derive(Debug)]
pub struct LossDetection {
    /// Configuration
    config: LossDetectionConfig,
    /// RTT statistics
    rtt_stats: RttStats,
    /// Sent packets by encryption level
    sent_packets: HashMap<EncryptionLevel, BTreeMap<u64, SentPacket>>,
    /// Largest packet numbers sent per level
    largest_sent: HashMap<EncryptionLevel, PacketNumber>,
    /// Largest acknowledged packet numbers per level
    largest_acked: HashMap<EncryptionLevel, PacketNumber>,
    /// Loss time for each encryption level
    loss_time: HashMap<EncryptionLevel, Option<Instant>>,
    /// Last probe sent time
    last_probe_time: HashMap<EncryptionLevel, Option<Instant>>,
    /// Probe timeout count
    pto_count: u32,
    /// Bytes in flight
    bytes_in_flight: usize,
    /// Lost packets pending retransmission
    lost_packets: VecDeque<SentPacket>,
}

impl LossDetection {
    pub fn new(config: LossDetectionConfig) -> Self {
        let rtt_stats = RttStats::new(config.initial_rtt);

        Self {
            config,
            rtt_stats,
            sent_packets: HashMap::new(),
            largest_sent: HashMap::new(),
            largest_acked: HashMap::new(),
            loss_time: HashMap::new(),
            last_probe_time: HashMap::new(),
            pto_count: 0,
            bytes_in_flight: 0,
            lost_packets: VecDeque::new(),
        }
    }

    /// Record a sent packet
    pub fn on_packet_sent(
        &mut self,
        level: EncryptionLevel,
        packet_number: PacketNumber,
        size: usize,
        ack_eliciting: bool,
        in_flight: bool,
        data: Bytes,
        is_probe: bool,
    ) {
        let packet = SentPacket {
            packet_number,
            time_sent: Instant::now(),
            size,
            ack_eliciting,
            in_flight,
            level,
            data,
            is_probe,
        };

        debug!(
            "Recording sent packet {} at level {:?}, size: {}, ack_eliciting: {}",
            packet_number.value(), level, size, ack_eliciting
        );

        // Update largest sent
        self.largest_sent.insert(level, packet_number);

        // Add to sent packets
        self.sent_packets
            .entry(level)
            .or_insert_with(BTreeMap::new)
            .insert(packet_number.value(), packet);

        // Update bytes in flight
        if in_flight {
            self.bytes_in_flight += size;
        }

        // Set loss detection timer
        self.set_loss_detection_timer();
    }

    /// Process an acknowledgment
    pub fn on_ack_received(
        &mut self,
        level: EncryptionLevel,
        ack_ranges: Vec<AckRange>,
        ack_delay: Duration,
    ) -> Result<Vec<SentPacket>> {
        debug!("Processing ACK for level {:?} with {} ranges", level, ack_ranges.len());

        let mut newly_acked = Vec::new();
        let mut largest_newly_acked = None;

        // Find newly acknowledged packets
        for range in &ack_ranges {
            if let Some(sent_packets) = self.sent_packets.get_mut(&level) {
                for pn in range.start.value()..=range.end.value() {
                    if let Some(packet) = sent_packets.remove(&pn) {
                        debug!("Packet {} acknowledged", pn);

                        // Update bytes in flight
                        if packet.in_flight {
                            self.bytes_in_flight = self.bytes_in_flight.saturating_sub(packet.size);
                        }

                        // Track largest newly acknowledged
                        if largest_newly_acked.is_none() || pn > largest_newly_acked.unwrap() {
                            largest_newly_acked = Some(pn);
                        }

                        newly_acked.push(packet);
                    }
                }
            }
        }

        // Update largest acknowledged
        if let Some(largest_pn) = largest_newly_acked {
            self.largest_acked.insert(level, PacketNumber(largest_pn));

            // Update RTT if this is the largest newly acknowledged packet
            if let Some(packet) = newly_acked.iter().find(|p| p.packet_number.value() == largest_pn) {
                let rtt_sample = packet.time_sent.elapsed();
                self.rtt_stats.update(rtt_sample, ack_delay);
                debug!("Updated RTT: smoothed={:?}, var={:?}",
                    self.rtt_stats.smoothed_rtt, self.rtt_stats.rtt_var);
            }
        }

        // Detect lost packets
        self.detect_lost_packets(level);

        // Reset PTO count if we have new acknowledgments
        if !newly_acked.is_empty() {
            self.pto_count = 0;
        }

        // Set loss detection timer
        self.set_loss_detection_timer();

        Ok(newly_acked)
    }

    /// Detect lost packets for a given encryption level
    fn detect_lost_packets(&mut self, level: EncryptionLevel) {
        let largest_acked = self.largest_acked.get(&level).copied();
        let Some(largest_acked) = largest_acked else { return; };

        let loss_delay = Duration::from_nanos(
            (self.rtt_stats.latest_rtt.as_nanos() as f64 * self.config.time_threshold) as u64
        ).max(Duration::from_millis(1)); // Minimum 1ms

        let lost_send_time = Instant::now() - loss_delay;

        let mut lost_packets = Vec::new();

        if let Some(sent_packets) = self.sent_packets.get_mut(&level) {
            let packets_to_check: Vec<_> = sent_packets.iter()
                .filter(|(&pn, _)| pn < largest_acked.value())
                .map(|(&pn, packet)| (pn, packet.clone()))
                .collect();

            for (pn, packet) in packets_to_check {
                let lost_by_time = packet.time_sent <= lost_send_time;
                let lost_by_threshold = largest_acked.value() - pn >= self.config.packet_threshold;

                if lost_by_time || lost_by_threshold {
                    debug!("Packet {} detected as lost (time: {}, threshold: {})",
                        pn, lost_by_time, lost_by_threshold);

                    if let Some(lost_packet) = sent_packets.remove(&pn) {
                        // Update bytes in flight
                        if lost_packet.in_flight {
                            self.bytes_in_flight = self.bytes_in_flight.saturating_sub(lost_packet.size);
                        }

                        lost_packets.push(lost_packet);
                    }
                }
            }
        }

        // Add to retransmission queue
        for packet in lost_packets {
            self.lost_packets.push_back(packet);
        }

        // Update loss time
        self.update_loss_time(level);
    }

    /// Update loss time for earliest loss timer
    fn update_loss_time(&mut self, level: EncryptionLevel) {
        let largest_acked = self.largest_acked.get(&level).copied();

        let loss_delay = Duration::from_nanos(
            (self.rtt_stats.latest_rtt.as_nanos() as f64 * self.config.time_threshold) as u64
        ).max(Duration::from_millis(1));

        let mut earliest_loss_time = None;

        if let Some(sent_packets) = self.sent_packets.get(&level) {
            for (&pn, packet) in sent_packets.iter() {
                // Only consider unacknowledged packets
                if let Some(largest_acked) = largest_acked {
                    if pn >= largest_acked.value() {
                        continue;
                    }
                }

                let loss_time = packet.time_sent + loss_delay;
                if earliest_loss_time.is_none() || loss_time < earliest_loss_time.unwrap() {
                    earliest_loss_time = Some(loss_time);
                }
            }
        }

        self.loss_time.insert(level, earliest_loss_time);
    }

    /// Set loss detection timer
    fn set_loss_detection_timer(&mut self) {
        // Find earliest loss time across all levels
        let mut earliest_loss_time = None;
        for &time in self.loss_time.values().flatten() {
            if earliest_loss_time.is_none() || time < earliest_loss_time.unwrap() {
                earliest_loss_time = Some(time);
            }
        }

        // If we have a loss time, use that
        if let Some(loss_time) = earliest_loss_time {
            debug!("Loss detection timer set for {:?}", loss_time);
            return;
        }

        // Otherwise, set PTO timer
        if self.bytes_in_flight > 0 {
            let pto_timeout = self.get_pto_timeout();
            debug!("PTO timer set for {:?}", pto_timeout);
        }
    }

    /// Get probe timeout duration
    fn get_pto_timeout(&self) -> Duration {
        let pto = self.rtt_stats.pto(self.config.max_ack_delay);
        let multiplier = 1u32 << self.pto_count.min(6); // Cap at 2^6 = 64
        std::cmp::min(pto * multiplier, self.config.max_pto)
    }

    /// Handle loss detection timer expiry
    pub fn on_loss_detection_timeout(&mut self) -> Vec<SentPacket> {
        // Check for lost packets first
        for level in [EncryptionLevel::Initial, EncryptionLevel::Handshake, EncryptionLevel::Application] {
            if let Some(loss_time) = self.loss_time.get(&level).copied().flatten() {
                if Instant::now() >= loss_time {
                    self.detect_lost_packets(level);
                }
            }
        }

        // If no packets to retransmit and we have bytes in flight, send probe
        if self.lost_packets.is_empty() && self.bytes_in_flight > 0 {
            self.pto_count += 1;
            debug!("PTO fired, count: {}", self.pto_count);
            return self.send_probe_packets();
        }

        Vec::new()
    }

    /// Send probe packets on PTO
    fn send_probe_packets(&mut self) -> Vec<SentPacket> {
        // In a real implementation, this would trigger sending new packets
        // For now, return empty vec to indicate probes should be sent
        Vec::new()
    }

    /// Get packets that need retransmission
    pub fn get_lost_packets(&mut self) -> Vec<SentPacket> {
        let mut lost = Vec::new();
        while let Some(packet) = self.lost_packets.pop_front() {
            lost.push(packet);
        }
        lost
    }

    /// Get RTT statistics
    pub fn rtt_stats(&self) -> &RttStats {
        &self.rtt_stats
    }

    /// Get bytes in flight
    pub fn bytes_in_flight(&self) -> usize {
        self.bytes_in_flight
    }

    /// Check if persistent congestion occurred
    pub fn in_persistent_congestion(&self, level: EncryptionLevel) -> bool {
        // Simplified check - in real implementation would be more sophisticated
        self.pto_count >= 2
    }

    /// Discard sent packets for a given encryption level
    pub fn discard_keys(&mut self, level: EncryptionLevel) {
        if let Some(sent_packets) = self.sent_packets.remove(&level) {
            // Remove from bytes in flight
            for packet in sent_packets.values() {
                if packet.in_flight {
                    self.bytes_in_flight = self.bytes_in_flight.saturating_sub(packet.size);
                }
            }
        }

        self.largest_sent.remove(&level);
        self.largest_acked.remove(&level);
        self.loss_time.remove(&level);
        self.last_probe_time.remove(&level);

        debug!("Discarded keys for level {:?}", level);
    }

    /// Get loss detection statistics
    pub fn stats(&self) -> LossDetectionStats {
        LossDetectionStats {
            smoothed_rtt: self.rtt_stats.smoothed_rtt,
            rtt_var: self.rtt_stats.rtt_var,
            min_rtt: self.rtt_stats.min_rtt,
            bytes_in_flight: self.bytes_in_flight,
            pto_count: self.pto_count,
            lost_packets: self.lost_packets.len(),
        }
    }
}

/// Loss detection statistics for monitoring
#[derive(Debug, Clone)]
pub struct LossDetectionStats {
    pub smoothed_rtt: Duration,
    pub rtt_var: Duration,
    pub min_rtt: Duration,
    pub bytes_in_flight: usize,
    pub pto_count: u32,
    pub lost_packets: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rtt_stats() {
        let mut rtt_stats = RttStats::new(Duration::from_millis(100));

        // First sample
        rtt_stats.update(Duration::from_millis(120), Duration::from_millis(5));
        assert!(rtt_stats.smoothed_rtt > Duration::from_millis(100));
        assert!(rtt_stats.min_rtt == Duration::from_millis(120));

        // Second sample
        rtt_stats.update(Duration::from_millis(80), Duration::from_millis(5));
        assert!(rtt_stats.min_rtt == Duration::from_millis(80));
    }

    #[test]
    fn test_loss_detection() {
        let config = LossDetectionConfig::default();
        let mut loss_detection = LossDetection::new(config);

        // Send a packet
        loss_detection.on_packet_sent(
            EncryptionLevel::Application,
            PacketNumber(1),
            1000,
            true,
            true,
            Bytes::from("test"),
            false,
        );

        assert_eq!(loss_detection.bytes_in_flight(), 1000);

        // Acknowledge the packet
        let ack_ranges = vec![AckRange::new(PacketNumber(1), PacketNumber(1))];
        let acked = loss_detection.on_ack_received(
            EncryptionLevel::Application,
            ack_ranges,
            Duration::from_millis(5),
        ).unwrap();

        assert_eq!(acked.len(), 1);
        assert_eq!(loss_detection.bytes_in_flight(), 0);
    }
}