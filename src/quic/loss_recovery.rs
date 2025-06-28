use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};
use tracing::{debug, warn, error};

use super::packet::PacketNumber;
use super::frame::Frame;
use super::error::{QuicError, Result};

/// Packet loss detection and recovery system
#[derive(Debug)]
pub struct LossRecovery {
    /// Packets sent but not yet acknowledged
    sent_packets: BTreeMap<PacketNumber, SentPacket>,
    /// Largest acknowledged packet number
    largest_acked: Option<PacketNumber>,
    /// Latest RTT measurement
    latest_rtt: Option<Duration>,
    /// Smoothed RTT
    smoothed_rtt: Option<Duration>,
    /// RTT variance
    rtt_var: Duration,
    /// Minimum RTT observed
    min_rtt: Option<Duration>,
    /// Packet reordering threshold
    packet_threshold: u64,
    /// Time threshold for packet loss detection
    time_threshold: f64,
    /// Probe timeout (PTO) count
    pto_count: u32,
    /// Loss detection timer
    loss_time: Option<Instant>,
    /// Last packet sent time
    last_packet_sent_time: Option<Instant>,
    /// Crypto packets that need special handling
    crypto_packets: VecDeque<PacketNumber>,
}

#[derive(Debug, Clone)]
pub struct SentPacket {
    pub packet_number: PacketNumber,
    pub time_sent: Instant,
    pub ack_eliciting: bool,
    pub in_flight: bool,
    pub frames: Vec<Frame>,
    pub size: usize,
}

#[derive(Debug, Clone)]
pub struct AckRange {
    pub start: PacketNumber,
    pub end: PacketNumber,
}

#[derive(Debug)]
pub struct LossDetectionResult {
    pub lost_packets: Vec<SentPacket>,
    pub newly_acked_packets: Vec<SentPacket>,
    pub ack_delay: Duration,
}

impl LossRecovery {
    pub fn new() -> Self {
        Self {
            sent_packets: BTreeMap::new(),
            largest_acked: None,
            latest_rtt: None,
            smoothed_rtt: None,
            rtt_var: Duration::from_millis(0),
            min_rtt: None,
            packet_threshold: 3, // RFC 9002 recommendation
            time_threshold: 9.0 / 8.0, // 1.125
            pto_count: 0,
            loss_time: None,
            last_packet_sent_time: None,
            crypto_packets: VecDeque::new(),
        }
    }

    /// Record a packet as sent
    pub fn on_packet_sent(
        &mut self,
        packet_number: PacketNumber,
        ack_eliciting: bool,
        in_flight: bool,
        frames: Vec<Frame>,
        size: usize,
    ) {
        let now = Instant::now();
        let sent_packet = SentPacket {
            packet_number,
            time_sent: now,
            ack_eliciting,
            in_flight,
            frames,
            size,
        };

        self.sent_packets.insert(packet_number, sent_packet);
        self.last_packet_sent_time = Some(now);

        // Track crypto packets separately
        for frame in &frames {
            if matches!(frame, Frame::Crypto { .. }) {
                self.crypto_packets.push_back(packet_number);
            }
        }

        debug!("Packet {} sent at {:?}", packet_number.value(), now);
        self.set_loss_detection_timer();
    }

    /// Process an ACK frame
    pub fn on_ack_received(
        &mut self,
        largest_acknowledged: PacketNumber,
        ack_delay: Duration,
        ack_ranges: Vec<AckRange>,
    ) -> Result<LossDetectionResult> {
        let now = Instant::now();
        let mut newly_acked = Vec::new();
        let mut lost_packets = Vec::new();

        // Update largest acknowledged
        if self.largest_acked.is_none() || largest_acknowledged > self.largest_acked.unwrap() {
            self.largest_acked = Some(largest_acknowledged);
        }

        // Process acknowledged packets
        for range in &ack_ranges {
            for pn_value in range.start.value()..=range.end.value() {
                let packet_number = PacketNumber::new(pn_value);
                if let Some(sent_packet) = self.sent_packets.remove(&packet_number) {
                    newly_acked.push(sent_packet.clone());
                    
                    // Update RTT if this is the largest acked packet
                    if packet_number == largest_acknowledged {
                        self.update_rtt(now.duration_since(sent_packet.time_sent), ack_delay);
                    }
                    
                    debug!("Packet {} acknowledged", packet_number.value());
                }
            }
        }

        // Detect lost packets
        lost_packets.extend(self.detect_lost_packets(now)?);

        // Reset PTO count on receiving ACK
        if !newly_acked.is_empty() {
            self.pto_count = 0;
        }

        self.set_loss_detection_timer();

        Ok(LossDetectionResult {
            lost_packets,
            newly_acked_packets: newly_acked,
            ack_delay,
        })
    }

    /// Detect lost packets based on reordering and timing
    fn detect_lost_packets(&mut self, now: Instant) -> Result<Vec<SentPacket>> {
        let mut lost_packets = Vec::new();
        
        if let Some(largest_acked) = self.largest_acked {
            let loss_delay = self.get_loss_delay();
            
            // Find packets to declare as lost
            let packets_to_remove: Vec<PacketNumber> = self.sent_packets
                .iter()
                .filter_map(|(pn, sent_packet)| {
                    // Packet threshold: packets significantly older than largest acked
                    let reorder_threshold = largest_acked.value().saturating_sub(self.packet_threshold);
                    
                    // Time threshold: packets sent long enough ago
                    let time_threshold = now.duration_since(sent_packet.time_sent) >= loss_delay;
                    
                    if pn.value() < reorder_threshold || time_threshold {
                        Some(*pn)
                    } else {
                        None
                    }
                })
                .collect();

            // Remove lost packets and add to result
            for pn in packets_to_remove {
                if let Some(lost_packet) = self.sent_packets.remove(&pn) {
                    warn!("Packet {} declared lost", pn.value());
                    lost_packets.push(lost_packet);
                }
            }
        }

        Ok(lost_packets)
    }

    /// Update RTT measurements
    fn update_rtt(&mut self, latest_rtt: Duration, ack_delay: Duration) {
        self.latest_rtt = Some(latest_rtt);

        // Update minimum RTT
        if self.min_rtt.is_none() || latest_rtt < self.min_rtt.unwrap() {
            self.min_rtt = Some(latest_rtt);
        }

        // Adjust for ack delay, but not below min_rtt
        let adjusted_rtt = if let Some(min_rtt) = self.min_rtt {
            latest_rtt.saturating_sub(ack_delay).max(min_rtt)
        } else {
            latest_rtt.saturating_sub(ack_delay)
        };

        // Update smoothed RTT and variance (RFC 9002)
        if let Some(smoothed_rtt) = self.smoothed_rtt {
            let rtt_sample = adjusted_rtt;
            let rtt_diff = if rtt_sample > smoothed_rtt {
                rtt_sample - smoothed_rtt
            } else {
                smoothed_rtt - rtt_sample
            };

            self.rtt_var = Duration::from_nanos(
                (self.rtt_var.as_nanos() as u64 * 3 + rtt_diff.as_nanos() as u64) / 4
            );
            
            self.smoothed_rtt = Some(Duration::from_nanos(
                (smoothed_rtt.as_nanos() as u64 * 7 + rtt_sample.as_nanos() as u64) / 8
            ));
        } else {
            self.smoothed_rtt = Some(adjusted_rtt);
            self.rtt_var = adjusted_rtt / 2;
        }

        debug!("RTT updated: latest={:?}, smoothed={:?}, var={:?}", 
               latest_rtt, self.smoothed_rtt, self.rtt_var);
    }

    /// Calculate loss delay threshold
    fn get_loss_delay(&self) -> Duration {
        if let Some(smoothed_rtt) = self.smoothed_rtt {
            let max_rtt = smoothed_rtt + 4 * self.rtt_var;
            Duration::from_nanos((max_rtt.as_nanos() as f64 * self.time_threshold) as u64)
        } else {
            Duration::from_millis(500) // Default if no RTT measurements
        }
    }

    /// Calculate Probe Timeout (PTO)
    pub fn get_pto_timeout(&self) -> Duration {
        let base_timeout = if let Some(smoothed_rtt) = self.smoothed_rtt {
            smoothed_rtt + 4 * self.rtt_var + Duration::from_millis(1)
        } else {
            Duration::from_millis(500) // Initial PTO
        };

        // Apply exponential backoff
        let backoff_factor = 2_u32.pow(self.pto_count);
        base_timeout * backoff_factor
    }

    /// Set the loss detection timer
    fn set_loss_detection_timer(&mut self) {
        let now = Instant::now();
        
        // Check if we need to set timer for lost packet detection
        if let Some(earliest_loss_time) = self.get_earliest_loss_time(now) {
            self.loss_time = Some(earliest_loss_time);
            return;
        }

        // Set PTO timer if we have ack-eliciting packets in flight
        if self.has_ack_eliciting_in_flight() {
            let pto_timeout = self.get_pto_timeout();
            if let Some(last_sent) = self.last_packet_sent_time {
                self.loss_time = Some(last_sent + pto_timeout);
            }
        } else {
            self.loss_time = None;
        }
    }

    /// Get the earliest time a packet can be declared lost
    fn get_earliest_loss_time(&self, now: Instant) -> Option<Instant> {
        if self.largest_acked.is_none() {
            return None;
        }

        let loss_delay = self.get_loss_delay();
        let mut earliest_loss_time = None;

        for sent_packet in self.sent_packets.values() {
            let loss_time = sent_packet.time_sent + loss_delay;
            if earliest_loss_time.is_none() || loss_time < earliest_loss_time.unwrap() {
                earliest_loss_time = Some(loss_time);
            }
        }

        earliest_loss_time
    }

    /// Check if there are ack-eliciting packets in flight
    fn has_ack_eliciting_in_flight(&self) -> bool {
        self.sent_packets.values().any(|p| p.ack_eliciting && p.in_flight)
    }

    /// Handle loss detection timer expiration
    pub fn on_loss_detection_timeout(&mut self) -> Result<Vec<SentPacket>> {
        let now = Instant::now();
        let mut lost_packets = Vec::new();

        if let Some(loss_time) = self.loss_time {
            if now >= loss_time {
                // Detect lost packets
                lost_packets.extend(self.detect_lost_packets(now)?);

                if lost_packets.is_empty() {
                    // PTO timer expired
                    self.pto_count += 1;
                    warn!("PTO timer expired (count: {})", self.pto_count);
                    
                    // Should send probe packets here
                    // For now, just reset the timer
                    self.set_loss_detection_timer();
                }
            }
        }

        Ok(lost_packets)
    }

    /// Get current RTT statistics
    pub fn rtt_stats(&self) -> RttStats {
        RttStats {
            latest_rtt: self.latest_rtt,
            smoothed_rtt: self.smoothed_rtt,
            rtt_var: self.rtt_var,
            min_rtt: self.min_rtt,
        }
    }

    /// Get packets that need to be retransmitted
    pub fn get_retransmittable_frames(&self, lost_packets: &[SentPacket]) -> Vec<Frame> {
        let mut frames = Vec::new();
        
        for packet in lost_packets {
            for frame in &packet.frames {
                // Only retransmit certain frame types
                match frame {
                    Frame::Stream { .. } |
                    Frame::Crypto { .. } |
                    Frame::ResetStream { .. } |
                    Frame::StopSending { .. } |
                    Frame::MaxData { .. } |
                    Frame::MaxStreamData { .. } |
                    Frame::MaxStreams { .. } |
                    Frame::DataBlocked { .. } |
                    Frame::StreamDataBlocked { .. } |
                    Frame::StreamsBlocked { .. } |
                    Frame::NewConnectionId { .. } |
                    Frame::RetireConnectionId { .. } => {
                        frames.push(frame.clone());
                    }
                    _ => {
                        // Don't retransmit ACK, PING, PADDING frames
                    }
                }
            }
        }
        
        frames
    }

    /// Clear all tracking state (for connection reset)
    pub fn reset(&mut self) {
        self.sent_packets.clear();
        self.largest_acked = None;
        self.pto_count = 0;
        self.loss_time = None;
        self.crypto_packets.clear();
    }

    /// Get loss detection metrics
    pub fn get_metrics(&self) -> LossRecoveryMetrics {
        LossRecoveryMetrics {
            packets_in_flight: self.sent_packets.len(),
            pto_count: self.pto_count,
            latest_rtt: self.latest_rtt,
            smoothed_rtt: self.smoothed_rtt,
            min_rtt: self.min_rtt,
            loss_detection_timer: self.loss_time,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RttStats {
    pub latest_rtt: Option<Duration>,
    pub smoothed_rtt: Option<Duration>,
    pub rtt_var: Duration,
    pub min_rtt: Option<Duration>,
}

#[derive(Debug, Clone)]
pub struct LossRecoveryMetrics {
    pub packets_in_flight: usize,
    pub pto_count: u32,
    pub latest_rtt: Option<Duration>,
    pub smoothed_rtt: Option<Duration>,
    pub min_rtt: Option<Duration>,
    pub loss_detection_timer: Option<Instant>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_loss_detection() {
        let mut recovery = LossRecovery::new();
        
        // Send some packets
        recovery.on_packet_sent(
            PacketNumber::new(1),
            true,
            true,
            vec![Frame::Ping],
            100,
        );
        
        recovery.on_packet_sent(
            PacketNumber::new(2),
            true,
            true,
            vec![Frame::Ping],
            100,
        );
        
        recovery.on_packet_sent(
            PacketNumber::new(3),
            true,
            true,
            vec![Frame::Ping],
            100,
        );
        
        // ACK packet 3, packet 1 should be declared lost due to reordering
        let ack_ranges = vec![AckRange {
            start: PacketNumber::new(3),
            end: PacketNumber::new(3),
        }];
        
        let result = recovery.on_ack_received(
            PacketNumber::new(3),
            Duration::from_millis(0),
            ack_ranges,
        ).unwrap();
        
        // Should have acked packet 3
        assert_eq!(result.newly_acked_packets.len(), 1);
        assert_eq!(result.newly_acked_packets[0].packet_number.value(), 3);
    }

    #[test]
    fn test_rtt_calculation() {
        let mut recovery = LossRecovery::new();
        
        // Send a packet
        recovery.on_packet_sent(
            PacketNumber::new(1),
            true,
            true,
            vec![Frame::Ping],
            100,
        );
        
        // Simulate 50ms RTT
        std::thread::sleep(Duration::from_millis(50));
        
        let ack_ranges = vec![AckRange {
            start: PacketNumber::new(1),
            end: PacketNumber::new(1),
        }];
        
        recovery.on_ack_received(
            PacketNumber::new(1),
            Duration::from_millis(5), // 5ms ack delay
            ack_ranges,
        ).unwrap();
        
        let stats = recovery.rtt_stats();
        assert!(stats.latest_rtt.is_some());
        assert!(stats.smoothed_rtt.is_some());
        assert!(stats.min_rtt.is_some());
    }
}