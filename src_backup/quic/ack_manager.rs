use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};
use tracing::{debug, trace};

use super::packet::PacketNumber;
use super::frame::Frame;
use super::error::{QuicError, Result};

/// ACK frame management and processing
#[derive(Debug)]
pub struct AckManager {
    /// Received packets that need to be acknowledged
    received_packets: BTreeSet<PacketNumber>,
    /// Largest received packet number
    largest_received: Option<PacketNumber>,
    /// Time when largest packet was received
    largest_received_time: Option<Instant>,
    /// ACK delay exponent for encoding
    ack_delay_exponent: u8,
    /// Maximum ACK delay
    max_ack_delay: Duration,
    /// Timer for sending delayed ACKs
    ack_timer: Option<Instant>,
    /// Number of ack-eliciting packets received since last ACK
    ack_eliciting_threshold: u32,
    /// Current count of ack-eliciting packets
    ack_eliciting_count: u32,
    /// Packets that have been acknowledged (for duplicate detection)
    acknowledged_packets: BTreeSet<PacketNumber>,
}

#[derive(Debug, Clone)]
pub struct AckFrame {
    pub largest_acknowledged: PacketNumber,
    pub ack_delay: Duration,
    pub ranges: Vec<AckRange>,
}

#[derive(Debug, Clone)]
pub struct AckRange {
    pub start: PacketNumber,
    pub end: PacketNumber,
}

impl AckManager {
    pub fn new() -> Self {
        Self {
            received_packets: BTreeSet::new(),
            largest_received: None,
            largest_received_time: None,
            ack_delay_exponent: 3, // Default from RFC 9000
            max_ack_delay: Duration::from_millis(25), // Default from RFC 9000
            ack_timer: None,
            ack_eliciting_threshold: 2, // ACK every 2 ack-eliciting packets
            ack_eliciting_count: 0,
            acknowledged_packets: BTreeSet::new(),
        }
    }

    /// Record a received packet
    pub fn on_packet_received(
        &mut self,
        packet_number: PacketNumber,
        ack_eliciting: bool,
        now: Instant,
    ) -> Result<bool> {
        // Check for duplicate packet
        if self.received_packets.contains(&packet_number) {
            debug!("Duplicate packet received: {}", packet_number.value());
            return Ok(false);
        }

        self.received_packets.insert(packet_number);

        // Update largest received
        if self.largest_received.is_none() || packet_number > self.largest_received.unwrap() {
            self.largest_received = Some(packet_number);
            self.largest_received_time = Some(now);
        }

        // Handle ack-eliciting packets
        if ack_eliciting {
            self.ack_eliciting_count += 1;
            
            // Immediate ACK conditions
            if self.should_send_immediate_ack() {
                trace!("Immediate ACK required for packet {}", packet_number.value());
                return Ok(true);
            }

            // Set delayed ACK timer
            if self.ack_timer.is_none() {
                self.ack_timer = Some(now + self.max_ack_delay);
            }
        }

        debug!("Packet {} received (ack_eliciting: {})", 
               packet_number.value(), ack_eliciting);
        
        Ok(false)
    }

    /// Check if an immediate ACK should be sent
    fn should_send_immediate_ack(&self) -> bool {
        // Send immediate ACK if we've received enough ack-eliciting packets
        self.ack_eliciting_count >= self.ack_eliciting_threshold
    }

    /// Check if ACK timer has expired
    pub fn should_send_ack(&self, now: Instant) -> bool {
        if let Some(timer) = self.ack_timer {
            now >= timer
        } else {
            false
        }
    }

    /// Generate an ACK frame
    pub fn generate_ack_frame(&mut self, now: Instant) -> Result<Option<AckFrame>> {
        if self.received_packets.is_empty() {
            return Ok(None);
        }

        let largest_acked = self.largest_received.unwrap();
        
        // Calculate ACK delay
        let ack_delay = if let Some(largest_time) = self.largest_received_time {
            now.duration_since(largest_time).min(self.max_ack_delay)
        } else {
            Duration::from_millis(0)
        };

        // Generate ACK ranges
        let ranges = self.generate_ack_ranges();

        // Mark packets as acknowledged
        for packet in &self.received_packets {
            self.acknowledged_packets.insert(*packet);
        }

        // Reset state
        self.ack_eliciting_count = 0;
        self.ack_timer = None;

        debug!("Generated ACK frame: largest={}, delay={:?}, ranges={}",
               largest_acked.value(), ack_delay, ranges.len());

        Ok(Some(AckFrame {
            largest_acknowledged: largest_acked,
            ack_delay,
            ranges,
        }))
    }

    /// Generate ACK ranges from received packets
    fn generate_ack_ranges(&self) -> Vec<AckRange> {
        let mut ranges = Vec::new();
        let mut current_start = None;
        let mut current_end = None;

        for &packet_number in &self.received_packets {
            match (current_start, current_end) {
                (None, None) => {
                    // First packet
                    current_start = Some(packet_number);
                    current_end = Some(packet_number);
                }
                (Some(start), Some(end)) => {
                    if packet_number.value() == end.value() + 1 {
                        // Consecutive packet, extend current range
                        current_end = Some(packet_number);
                    } else {
                        // Gap found, finish current range and start new one
                        ranges.push(AckRange {
                            start,
                            end,
                        });
                        current_start = Some(packet_number);
                        current_end = Some(packet_number);
                    }
                }
                _ => unreachable!(),
            }
        }

        // Add final range
        if let (Some(start), Some(end)) = (current_start, current_end) {
            ranges.push(AckRange { start, end });
        }

        // Reverse ranges (largest first, as per QUIC spec)
        ranges.reverse();
        ranges
    }

    /// Process an incoming ACK frame (for detecting ACK of ACKs)
    pub fn on_ack_frame_received(&mut self, ack_frame: &AckFrame) -> Result<()> {
        // In QUIC, ACK frames themselves are not acknowledged
        // This method could be used for other ACK-related processing
        trace!("ACK frame received acknowledging up to packet {}", 
               ack_frame.largest_acknowledged.value());
        Ok(())
    }

    /// Clean up old acknowledged packets to prevent memory growth
    pub fn cleanup_old_packets(&mut self, cutoff: PacketNumber) {
        // Remove acknowledged packets older than cutoff
        self.acknowledged_packets = self.acknowledged_packets
            .split_off(&cutoff);
        
        // Remove received packets older than cutoff
        self.received_packets = self.received_packets
            .split_off(&cutoff);
    }

    /// Get ACK manager statistics
    pub fn get_stats(&self) -> AckManagerStats {
        AckManagerStats {
            received_packets_count: self.received_packets.len(),
            largest_received: self.largest_received,
            ack_eliciting_count: self.ack_eliciting_count,
            ack_timer_set: self.ack_timer.is_some(),
            acknowledged_packets_count: self.acknowledged_packets.len(),
        }
    }

    /// Force generation of ACK frame (for immediate ACK)
    pub fn force_ack(&mut self, now: Instant) -> Result<Option<AckFrame>> {
        if !self.received_packets.is_empty() {
            self.generate_ack_frame(now)
        } else {
            Ok(None)
        }
    }

    /// Check if there are unacknowledged packets
    pub fn has_unacknowledged_packets(&self) -> bool {
        !self.received_packets.is_empty()
    }

    /// Get the next ACK timer expiration
    pub fn next_ack_timeout(&self) -> Option<Instant> {
        self.ack_timer
    }

    /// Update ACK configuration
    pub fn configure(
        &mut self,
        max_ack_delay: Duration,
        ack_delay_exponent: u8,
        ack_eliciting_threshold: u32,
    ) {
        self.max_ack_delay = max_ack_delay;
        self.ack_delay_exponent = ack_delay_exponent;
        self.ack_eliciting_threshold = ack_eliciting_threshold;
    }
}

#[derive(Debug, Clone)]
pub struct AckManagerStats {
    pub received_packets_count: usize,
    pub largest_received: Option<PacketNumber>,
    pub ack_eliciting_count: u32,
    pub ack_timer_set: bool,
    pub acknowledged_packets_count: usize,
}

/// ACK frame encoder/decoder
pub mod ack_encoding {
    use super::*;
    use bytes::{Bytes, BytesMut, BufMut, Buf};

    pub fn encode_ack_frame(ack: &AckFrame) -> Bytes {
        let mut buf = BytesMut::new();
        
        // Frame type (ACK = 0x02)
        buf.put_u8(0x02);
        
        // Largest Acknowledged
        encode_varint(&mut buf, ack.largest_acknowledged.value());
        
        // ACK Delay (encoded with ack_delay_exponent)
        let ack_delay_encoded = ack.ack_delay.as_micros() as u64 / 8; // Simplified
        encode_varint(&mut buf, ack_delay_encoded);
        
        // ACK Range Count
        encode_varint(&mut buf, (ack.ranges.len() - 1) as u64);
        
        // First ACK Range
        if let Some(first_range) = ack.ranges.first() {
            let range_length = first_range.end.value() - first_range.start.value();
            encode_varint(&mut buf, range_length);
        }
        
        // Additional ACK Ranges
        let mut previous_end = ack.ranges.first().map(|r| r.start.value()).unwrap_or(0);
        
        for range in ack.ranges.iter().skip(1) {
            // Gap
            let gap = previous_end - range.end.value() - 1;
            encode_varint(&mut buf, gap);
            
            // Range Length
            let range_length = range.end.value() - range.start.value();
            encode_varint(&mut buf, range_length);
            
            previous_end = range.start.value();
        }
        
        buf.freeze()
    }

    pub fn decode_ack_frame(mut data: Bytes) -> Result<AckFrame> {
        if data.is_empty() {
            return Err(QuicError::Protocol(
                crate::quic::error::ProtocolError::InvalidFrameFormat(
                    "Empty ACK frame".to_string()
                )
            ));
        }
        
        // Frame type
        let frame_type = data.get_u8();
        if frame_type != 0x02 {
            return Err(QuicError::Protocol(
                crate::quic::error::ProtocolError::InvalidFrameFormat(
                    format!("Invalid ACK frame type: {}", frame_type)
                )
            ));
        }
        
        // Largest Acknowledged
        let largest_acked = PacketNumber::new(decode_varint(&mut data)?);
        
        // ACK Delay
        let ack_delay_encoded = decode_varint(&mut data)?;
        let ack_delay = Duration::from_micros(ack_delay_encoded * 8);
        
        // ACK Range Count
        let range_count = decode_varint(&mut data)? + 1;
        
        let mut ranges = Vec::new();
        let mut current_largest = largest_acked.value();
        
        // First ACK Range
        let first_range_length = decode_varint(&mut data)?;
        let first_range_start = current_largest - first_range_length;
        ranges.push(AckRange {
            start: PacketNumber::new(first_range_start),
            end: PacketNumber::new(current_largest),
        });
        current_largest = first_range_start;
        
        // Additional ranges
        for _ in 1..range_count {
            let gap = decode_varint(&mut data)?;
            let range_length = decode_varint(&mut data)?;
            
            let range_end = current_largest - gap - 1;
            let range_start = range_end - range_length;
            
            ranges.push(AckRange {
                start: PacketNumber::new(range_start),
                end: PacketNumber::new(range_end),
            });
            
            current_largest = range_start;
        }
        
        Ok(AckFrame {
            largest_acknowledged: largest_acked,
            ack_delay,
            ranges,
        })
    }

    fn encode_varint(buf: &mut BytesMut, mut value: u64) {
        if value < 64 {
            buf.put_u8(value as u8);
        } else if value < 16384 {
            buf.put_u16((value as u16) | 0x4000);
        } else if value < 1073741824 {
            buf.put_u32((value as u32) | 0x80000000);
        } else {
            buf.put_u64(value | 0xC000000000000000);
        }
    }

    fn decode_varint(buf: &mut Bytes) -> Result<u64> {
        if buf.is_empty() {
            return Err(QuicError::Protocol(
                crate::quic::error::ProtocolError::InvalidFrameFormat(
                    "Insufficient data for varint".to_string()
                )
            ));
        }
        
        let first_byte = buf[0];
        match first_byte >> 6 {
            0 => Ok(buf.get_u8() as u64),
            1 => Ok((buf.get_u16() & 0x3FFF) as u64),
            2 => Ok((buf.get_u32() & 0x3FFFFFFF) as u64),
            3 => Ok(buf.get_u64() & 0x3FFFFFFFFFFFFFFF),
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ack_range_generation() {
        let mut ack_manager = AckManager::new();
        let now = Instant::now();
        
        // Receive packets 1, 2, 3, 5, 6 (missing 4)
        ack_manager.on_packet_received(PacketNumber::new(1), true, now).unwrap();
        ack_manager.on_packet_received(PacketNumber::new(2), true, now).unwrap();
        ack_manager.on_packet_received(PacketNumber::new(3), true, now).unwrap();
        ack_manager.on_packet_received(PacketNumber::new(5), true, now).unwrap();
        ack_manager.on_packet_received(PacketNumber::new(6), true, now).unwrap();
        
        let ack_frame = ack_manager.generate_ack_frame(now).unwrap().unwrap();
        
        // Should generate two ranges: [5,6] and [1,3]
        assert_eq!(ack_frame.ranges.len(), 2);
        assert_eq!(ack_frame.largest_acknowledged.value(), 6);
        
        // First range should be [5,6]
        assert_eq!(ack_frame.ranges[0].start.value(), 5);
        assert_eq!(ack_frame.ranges[0].end.value(), 6);
        
        // Second range should be [1,3]
        assert_eq!(ack_frame.ranges[1].start.value(), 1);
        assert_eq!(ack_frame.ranges[1].end.value(), 3);
    }

    #[test]
    fn test_immediate_ack_trigger() {
        let mut ack_manager = AckManager::new();
        let now = Instant::now();
        
        // First ack-eliciting packet shouldn't trigger immediate ACK
        let immediate = ack_manager.on_packet_received(PacketNumber::new(1), true, now).unwrap();
        assert!(!immediate);
        
        // Second ack-eliciting packet should trigger immediate ACK
        let immediate = ack_manager.on_packet_received(PacketNumber::new(2), true, now).unwrap();
        assert!(immediate);
    }

    #[test]
    fn test_ack_encoding_decoding() {
        use ack_encoding::*;
        
        let original_ack = AckFrame {
            largest_acknowledged: PacketNumber::new(10),
            ack_delay: Duration::from_millis(5),
            ranges: vec![
                AckRange {
                    start: PacketNumber::new(8),
                    end: PacketNumber::new(10),
                },
                AckRange {
                    start: PacketNumber::new(5),
                    end: PacketNumber::new(6),
                },
            ],
        };
        
        let encoded = encode_ack_frame(&original_ack);
        let decoded = decode_ack_frame(encoded).unwrap();
        
        assert_eq!(decoded.largest_acknowledged.value(), 10);
        assert_eq!(decoded.ranges.len(), 2);
    }
}