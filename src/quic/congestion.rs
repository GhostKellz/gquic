use std::time::{Duration, Instant};
use tracing::{debug, warn};

/// Congestion control algorithm for QUIC
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CongestionAlgorithm {
    NewReno,
    Cubic,
    Bbr,
}

/// Congestion controller state
#[derive(Debug)]
pub struct CongestionController {
    algorithm: CongestionAlgorithm,
    congestion_window: u64,
    ssthresh: u64,
    bytes_in_flight: u64,
    max_datagram_size: u64,
    min_congestion_window: u64,
    initial_congestion_window: u64,
    loss_recovery_start_time: Option<Instant>,
    rtt_stats: RttStats,
}

/// Round-trip time statistics
#[derive(Debug)]
pub struct RttStats {
    pub min_rtt: Option<Duration>,
    pub smoothed_rtt: Option<Duration>,
    pub rtt_variance: Duration,
    pub latest_rtt: Option<Duration>,
}

impl Default for RttStats {
    fn default() -> Self {
        Self {
            min_rtt: None,
            smoothed_rtt: None,
            rtt_variance: Duration::from_millis(0),
            latest_rtt: None,
        }
    }
}

impl CongestionController {
    /// Create a new congestion controller
    pub fn new(algorithm: CongestionAlgorithm, max_datagram_size: u64) -> Self {
        let initial_congestion_window = 10 * max_datagram_size; // RFC 9002 recommendation
        let min_congestion_window = 2 * max_datagram_size;
        
        Self {
            algorithm,
            congestion_window: initial_congestion_window,
            ssthresh: u64::MAX,
            bytes_in_flight: 0,
            max_datagram_size,
            min_congestion_window,
            initial_congestion_window,
            loss_recovery_start_time: None,
            rtt_stats: RttStats::default(),
        }
    }
    
    /// Get current congestion window size
    pub fn congestion_window(&self) -> u64 {
        self.congestion_window
    }
    
    /// Get bytes currently in flight
    pub fn bytes_in_flight(&self) -> u64 {
        self.bytes_in_flight
    }
    
    /// Check if we can send data
    pub fn can_send(&self, bytes: u64) -> bool {
        self.bytes_in_flight + bytes <= self.congestion_window
    }
    
    /// Called when a packet is sent
    pub fn on_packet_sent(&mut self, bytes: u64, _packet_number: u64, _sent_time: Instant) {
        self.bytes_in_flight += bytes;
        debug!("Packet sent: {} bytes, {} in flight", bytes, self.bytes_in_flight);
    }
    
    /// Called when packets are acknowledged
    pub fn on_packets_acked(&mut self, acked_bytes: u64, largest_acked_time: Instant) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(acked_bytes);
        
        // Update RTT if this is the largest acknowledged packet
        if let Some(latest_rtt) = self.rtt_stats.latest_rtt {
            self.update_rtt(latest_rtt);
        }
        
        // Increase congestion window based on algorithm
        match self.algorithm {
            CongestionAlgorithm::NewReno => {
                self.new_reno_on_ack(acked_bytes);
            }
            CongestionAlgorithm::Cubic => {
                self.cubic_on_ack(acked_bytes);
            }
            CongestionAlgorithm::Bbr => {
                self.bbr_on_ack(acked_bytes);
            }
        }
        
        debug!("Packets acked: {} bytes, cwnd: {}, in_flight: {}", 
               acked_bytes, self.congestion_window, self.bytes_in_flight);
    }
    
    /// Called when packet loss is detected
    pub fn on_packets_lost(&mut self, lost_bytes: u64, _largest_lost_packet: u64) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(lost_bytes);
        
        // Enter loss recovery if not already in it
        if self.loss_recovery_start_time.is_none() {
            self.loss_recovery_start_time = Some(Instant::now());
            
            // Reduce congestion window
            self.ssthresh = std::cmp::max(
                self.congestion_window / 2,
                self.min_congestion_window
            );
            self.congestion_window = self.ssthresh;
            
            warn!("Packet loss detected: {} bytes lost, cwnd reduced to {}", 
                  lost_bytes, self.congestion_window);
        }
    }
    
    /// Update RTT statistics
    pub fn update_rtt(&mut self, latest_rtt: Duration) {
        self.rtt_stats.latest_rtt = Some(latest_rtt);
        
        // Update minimum RTT
        if self.rtt_stats.min_rtt.is_none() || latest_rtt < self.rtt_stats.min_rtt.unwrap() {
            self.rtt_stats.min_rtt = Some(latest_rtt);
        }
        
        // Update smoothed RTT using exponentially weighted moving average
        if let Some(smoothed_rtt) = self.rtt_stats.smoothed_rtt {
            let rtt_diff = if latest_rtt > smoothed_rtt {
                latest_rtt - smoothed_rtt
            } else {
                smoothed_rtt - latest_rtt
            };
            
            self.rtt_stats.rtt_variance = Duration::from_nanos(
                (self.rtt_stats.rtt_variance.as_nanos() as u64 * 3 + rtt_diff.as_nanos() as u64) / 4
            );
            
            self.rtt_stats.smoothed_rtt = Some(Duration::from_nanos(
                (smoothed_rtt.as_nanos() as u64 * 7 + latest_rtt.as_nanos() as u64) / 8
            ));
        } else {
            self.rtt_stats.smoothed_rtt = Some(latest_rtt);
            self.rtt_stats.rtt_variance = latest_rtt / 2;
        }
    }
    
    /// NewReno congestion control on ACK
    fn new_reno_on_ack(&mut self, acked_bytes: u64) {
        if self.congestion_window < self.ssthresh {
            // Slow start: increase congestion window by acked bytes
            self.congestion_window += acked_bytes;
        } else {
            // Congestion avoidance: increase by max_datagram_size per RTT
            let increase = (self.max_datagram_size * acked_bytes) / self.congestion_window;
            self.congestion_window += increase;
        }
    }
    
    /// CUBIC congestion control on ACK (simplified)
    fn cubic_on_ack(&mut self, acked_bytes: u64) {
        // Simplified CUBIC implementation
        // In production, this would use the full CUBIC algorithm
        if self.congestion_window < self.ssthresh {
            // Slow start
            self.congestion_window += acked_bytes;
        } else {
            // CUBIC increase (simplified)
            let increase = self.max_datagram_size / (self.congestion_window / self.max_datagram_size);
            self.congestion_window += increase;
        }
    }
    
    /// BBR congestion control on ACK (simplified)
    fn bbr_on_ack(&mut self, _acked_bytes: u64) {
        // Simplified BBR implementation
        // BBR focuses on bandwidth and RTT measurements
        // This is a placeholder - real BBR is much more complex
        if let Some(min_rtt) = self.rtt_stats.min_rtt {
            let target_cwnd = self.estimate_bandwidth() * min_rtt.as_millis() as u64 / 1000;
            
            if self.congestion_window < target_cwnd {
                self.congestion_window += self.max_datagram_size;
            }
        }
    }
    
    /// Estimate bandwidth (simplified for BBR)
    fn estimate_bandwidth(&self) -> u64 {
        // Simplified bandwidth estimation
        // In real BBR, this would track delivery rate over multiple RTTs
        if let Some(rtt) = self.rtt_stats.smoothed_rtt {
            self.congestion_window * 1000 / rtt.as_millis().max(1) as u64
        } else {
            self.congestion_window
        }
    }
    
    /// Exit loss recovery if applicable
    pub fn maybe_exit_loss_recovery(&mut self, largest_acked_packet: u64, sent_time: Instant) {
        if let Some(recovery_start) = self.loss_recovery_start_time {
            if sent_time > recovery_start {
                self.loss_recovery_start_time = None;
                debug!("Exited loss recovery");
            }
        }
    }
    
    /// Get the current retransmission timeout
    pub fn pto_timeout(&self) -> Duration {
        if let Some(smoothed_rtt) = self.rtt_stats.smoothed_rtt {
            smoothed_rtt + 4 * self.rtt_stats.rtt_variance + Duration::from_millis(1)
        } else {
            Duration::from_millis(500) // Default PTO
        }
    }
}

/// Flow control for streams and connections
#[derive(Debug)]
pub struct FlowController {
    /// Maximum data that can be sent
    pub max_data: u64,
    /// Data already sent
    pub sent_data: u64,
    /// Maximum data that can be received
    pub max_receive_data: u64,
    /// Data already received
    pub received_data: u64,
}

impl FlowController {
    pub fn new(initial_max_data: u64, initial_max_receive_data: u64) -> Self {
        Self {
            max_data: initial_max_data,
            sent_data: 0,
            max_receive_data: initial_max_receive_data,
            received_data: 0,
        }
    }
    
    /// Check if we can send the given amount of data
    pub fn can_send(&self, bytes: u64) -> bool {
        self.sent_data + bytes <= self.max_data
    }
    
    /// Record data sent
    pub fn on_data_sent(&mut self, bytes: u64) -> Result<(), &'static str> {
        if !self.can_send(bytes) {
            return Err("Flow control limit exceeded");
        }
        self.sent_data += bytes;
        Ok(())
    }
    
    /// Record data received
    pub fn on_data_received(&mut self, bytes: u64) -> Result<(), &'static str> {
        if self.received_data + bytes > self.max_receive_data {
            return Err("Receive flow control limit exceeded");
        }
        self.received_data += bytes;
        Ok(())
    }
    
    /// Update maximum sendable data
    pub fn update_max_data(&mut self, new_max: u64) {
        if new_max > self.max_data {
            self.max_data = new_max;
            debug!("Updated max_data to {}", new_max);
        }
    }
    
    /// Get available send window
    pub fn send_window(&self) -> u64 {
        self.max_data.saturating_sub(self.sent_data)
    }
    
    /// Get available receive window
    pub fn receive_window(&self) -> u64 {
        self.max_receive_data.saturating_sub(self.received_data)
    }
}