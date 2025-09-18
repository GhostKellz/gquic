//! Explicit Congestion Notification (ECN) Support
//!
//! ECN allows network devices to signal congestion without dropping packets,
//! enabling more efficient congestion control and better network performance.

use crate::{QuicError, QuicResult};
use std::net::{SocketAddr, IpAddr};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};
use std::collections::VecDeque;

/// ECN codepoints as defined in RFC 3168
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EcnCodepoint {
    /// Not ECN-Capable Transport (Not-ECT)
    NotEct = 0b00,
    /// ECN-Capable Transport (0) (ECT(0))
    Ect0 = 0b10,
    /// ECN-Capable Transport (1) (ECT(1))
    Ect1 = 0b01,
    /// Congestion Experienced (CE)
    Ce = 0b11,
}

impl EcnCodepoint {
    /// Parse ECN bits from IP TOS/Traffic Class field
    pub fn from_bits(bits: u8) -> Self {
        match bits & 0b11 {
            0b00 => Self::NotEct,
            0b10 => Self::Ect0,
            0b01 => Self::Ect1,
            0b11 => Self::Ce,
            _ => unreachable!(),
        }
    }

    /// Convert to bits for IP TOS/Traffic Class field
    pub fn to_bits(self) -> u8 {
        self as u8
    }

    /// Check if ECN capable
    pub fn is_ect(self) -> bool {
        matches!(self, Self::Ect0 | Self::Ect1)
    }

    /// Check if congestion experienced
    pub fn is_ce(self) -> bool {
        self == Self::Ce
    }
}

/// ECN controller for managing ECN state and congestion response
pub struct EcnController {
    /// ECN configuration
    config: EcnConfig,
    /// ECN state
    state: Arc<RwLock<EcnState>>,
    /// ECN counters
    counters: Arc<RwLock<EcnCounters>>,
    /// Congestion events
    congestion_events: Arc<Mutex<VecDeque<CongestionEvent>>>,
    /// ECN validation state
    validation: Arc<RwLock<EcnValidation>>,
}

/// ECN configuration
#[derive(Debug, Clone)]
pub struct EcnConfig {
    /// Enable ECN
    pub enabled: bool,
    /// ECN marking scheme (ECT(0) or ECT(1))
    pub marking_scheme: EcnMarkingScheme,
    /// Enable ECN validation
    pub validation_enabled: bool,
    /// Validation timeout
    pub validation_timeout: Duration,
    /// CE threshold for congestion response
    pub ce_threshold: f64,
    /// Enable L4S (Low Latency, Low Loss, Scalable throughput)
    pub l4s_enabled: bool,
    /// AccECN (Accurate ECN) support
    pub accecn_enabled: bool,
}

impl Default for EcnConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            marking_scheme: EcnMarkingScheme::Ect0,
            validation_enabled: true,
            validation_timeout: Duration::from_secs(10),
            ce_threshold: 0.01, // 1% CE marks trigger congestion response
            l4s_enabled: false,
            accecn_enabled: false,
        }
    }
}

/// ECN marking scheme
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EcnMarkingScheme {
    /// Use ECT(0) for all packets
    Ect0,
    /// Use ECT(1) for all packets
    Ect1,
    /// Alternate between ECT(0) and ECT(1)
    Alternate,
    /// Use ECT(1) for L4S traffic
    L4s,
}

/// ECN state
#[derive(Debug, Clone)]
struct EcnState {
    /// ECN capability negotiated
    capable: bool,
    /// ECN validation passed
    validated: bool,
    /// Current marking codepoint
    current_marking: EcnCodepoint,
    /// Last CE received time
    last_ce_time: Option<Instant>,
    /// Congestion window reduction time
    last_cwnd_reduction: Option<Instant>,
}

/// ECN counters for tracking
#[derive(Debug, Clone, Default)]
struct EcnCounters {
    /// Packets sent with ECT(0)
    ect0_sent: u64,
    /// Packets sent with ECT(1)
    ect1_sent: u64,
    /// Packets sent with CE
    ce_sent: u64,
    /// Packets received with ECT(0)
    ect0_received: u64,
    /// Packets received with ECT(1)
    ect1_received: u64,
    /// Packets received with CE
    ce_received: u64,
    /// Packets received without ECN
    not_ect_received: u64,
    /// Total packets sent
    total_sent: u64,
    /// Total packets received
    total_received: u64,
}

/// Congestion event
#[derive(Debug, Clone)]
struct CongestionEvent {
    /// Event timestamp
    timestamp: Instant,
    /// Event type
    event_type: CongestionEventType,
    /// ECN codepoint that triggered event
    codepoint: EcnCodepoint,
    /// Congestion window at event
    cwnd: u64,
}

/// Congestion event type
#[derive(Debug, Clone, Copy, PartialEq)]
enum CongestionEventType {
    /// CE mark received
    CeMark,
    /// Packet loss detected
    PacketLoss,
    /// ECN validation failed
    ValidationFailed,
}

/// ECN validation state
#[derive(Debug, Clone)]
struct EcnValidation {
    /// Validation in progress
    in_progress: bool,
    /// Validation start time
    start_time: Option<Instant>,
    /// Test packets sent
    test_sent: u64,
    /// Test packets acknowledged
    test_acked: u64,
    /// CE marks during validation
    ce_during_test: u64,
}

impl EcnController {
    /// Create a new ECN controller
    pub fn new(config: EcnConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(EcnState {
                capable: false,
                validated: false,
                current_marking: EcnCodepoint::NotEct,
                last_ce_time: None,
                last_cwnd_reduction: None,
            })),
            counters: Arc::new(RwLock::new(EcnCounters::default())),
            congestion_events: Arc::new(Mutex::new(VecDeque::with_capacity(100))),
            validation: Arc::new(RwLock::new(EcnValidation {
                in_progress: false,
                start_time: None,
                test_sent: 0,
                test_acked: 0,
                ce_during_test: 0,
            })),
        }
    }

    /// Start ECN capability negotiation
    pub async fn start_negotiation(&self) -> QuicResult<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let mut state = self.state.write().await;
        state.capable = true;

        if self.config.validation_enabled {
            self.start_validation().await?;
        } else {
            state.validated = true;
            state.current_marking = self.get_initial_marking();
        }

        Ok(())
    }

    /// Start ECN validation
    async fn start_validation(&self) -> QuicResult<()> {
        let mut validation = self.validation.write().await;
        validation.in_progress = true;
        validation.start_time = Some(Instant::now());
        validation.test_sent = 0;
        validation.test_acked = 0;
        validation.ce_during_test = 0;

        Ok(())
    }

    /// Get ECN marking for outgoing packet
    pub async fn get_packet_marking(&self, packet_num: u64) -> EcnCodepoint {
        let state = self.state.read().await;

        if !state.capable || !state.validated {
            return EcnCodepoint::NotEct;
        }

        // Update counters
        let mut counters = self.counters.write().await;
        counters.total_sent += 1;

        // Determine marking based on scheme
        let marking = match self.config.marking_scheme {
            EcnMarkingScheme::Ect0 => EcnCodepoint::Ect0,
            EcnMarkingScheme::Ect1 => EcnCodepoint::Ect1,
            EcnMarkingScheme::Alternate => {
                if packet_num % 2 == 0 {
                    EcnCodepoint::Ect0
                } else {
                    EcnCodepoint::Ect1
                }
            }
            EcnMarkingScheme::L4s => {
                if self.config.l4s_enabled {
                    EcnCodepoint::Ect1
                } else {
                    EcnCodepoint::Ect0
                }
            }
        };

        // Update marking counters
        match marking {
            EcnCodepoint::Ect0 => counters.ect0_sent += 1,
            EcnCodepoint::Ect1 => counters.ect1_sent += 1,
            _ => {}
        }

        marking
    }

    /// Process received packet with ECN info
    pub async fn process_received_packet(
        &self,
        codepoint: EcnCodepoint,
        packet_num: u64,
    ) -> QuicResult<()> {
        // Update counters
        let mut counters = self.counters.write().await;
        counters.total_received += 1;

        match codepoint {
            EcnCodepoint::NotEct => counters.not_ect_received += 1,
            EcnCodepoint::Ect0 => counters.ect0_received += 1,
            EcnCodepoint::Ect1 => counters.ect1_received += 1,
            EcnCodepoint::Ce => {
                counters.ce_received += 1;
                drop(counters);
                self.handle_ce_mark(packet_num).await?;
            }
        }

        // Update validation if in progress
        if self.validation.read().await.in_progress {
            self.update_validation(codepoint).await?;
        }

        Ok(())
    }

    /// Handle CE mark
    async fn handle_ce_mark(&self, packet_num: u64) -> QuicResult<()> {
        let mut state = self.state.write().await;
        let now = Instant::now();
        state.last_ce_time = Some(now);

        // Record congestion event
        let mut events = self.congestion_events.lock().await;
        events.push_back(CongestionEvent {
            timestamp: now,
            event_type: CongestionEventType::CeMark,
            codepoint: EcnCodepoint::Ce,
            cwnd: 0, // Will be filled by congestion controller
        });

        // Limit event queue size
        if events.len() > 100 {
            events.pop_front();
        }

        Ok(())
    }

    /// Update ECN validation
    async fn update_validation(&self, codepoint: EcnCodepoint) -> QuicResult<()> {
        let mut validation = self.validation.write().await;

        if !validation.in_progress {
            return Ok(());
        }

        validation.test_acked += 1;

        if codepoint == EcnCodepoint::Ce {
            validation.ce_during_test += 1;
        }

        // Check if validation complete
        if validation.test_acked >= 10 {
            let ce_rate = validation.ce_during_test as f64 / validation.test_acked as f64;

            if ce_rate < 0.5 {
                // Validation passed
                let mut state = self.state.write().await;
                state.validated = true;
                state.current_marking = self.get_initial_marking();
                validation.in_progress = false;
            } else {
                // Validation failed - disable ECN
                let mut state = self.state.write().await;
                state.capable = false;
                state.validated = false;
                validation.in_progress = false;

                // Record failure event
                let mut events = self.congestion_events.lock().await;
                events.push_back(CongestionEvent {
                    timestamp: Instant::now(),
                    event_type: CongestionEventType::ValidationFailed,
                    codepoint: EcnCodepoint::NotEct,
                    cwnd: 0,
                });
            }
        }

        // Check timeout
        if let Some(start) = validation.start_time {
            if Instant::now().duration_since(start) > self.config.validation_timeout {
                validation.in_progress = false;
                let mut state = self.state.write().await;
                state.capable = false;
            }
        }

        Ok(())
    }

    /// Check if congestion response needed
    pub async fn should_reduce_cwnd(&self) -> bool {
        let state = self.state.read().await;

        if let Some(last_ce) = state.last_ce_time {
            if let Some(last_reduction) = state.last_cwnd_reduction {
                // Don't reduce again within RTT
                if last_ce > last_reduction {
                    return true;
                }
            } else {
                return true;
            }
        }

        false
    }

    /// Mark congestion window reduction
    pub async fn mark_cwnd_reduction(&self) {
        let mut state = self.state.write().await;
        state.last_cwnd_reduction = Some(Instant::now());
    }

    /// Get ECN statistics
    pub async fn get_stats(&self) -> EcnStats {
        let counters = self.counters.read().await;
        let state = self.state.read().await;

        let ce_rate = if counters.total_received > 0 {
            counters.ce_received as f64 / counters.total_received as f64
        } else {
            0.0
        };

        EcnStats {
            capable: state.capable,
            validated: state.validated,
            ect0_sent: counters.ect0_sent,
            ect1_sent: counters.ect1_sent,
            ce_received: counters.ce_received,
            total_sent: counters.total_sent,
            total_received: counters.total_received,
            ce_rate,
        }
    }

    /// Get initial marking based on configuration
    fn get_initial_marking(&self) -> EcnCodepoint {
        match self.config.marking_scheme {
            EcnMarkingScheme::Ect0 => EcnCodepoint::Ect0,
            EcnMarkingScheme::Ect1 => EcnCodepoint::Ect1,
            EcnMarkingScheme::Alternate => EcnCodepoint::Ect0,
            EcnMarkingScheme::L4s => {
                if self.config.l4s_enabled {
                    EcnCodepoint::Ect1
                } else {
                    EcnCodepoint::Ect0
                }
            }
        }
    }

    /// Process ACK with ECN counts (for AccECN)
    pub async fn process_ack_ecn(
        &self,
        ect0_count: u64,
        ect1_count: u64,
        ce_count: u64,
    ) -> QuicResult<()> {
        if !self.config.accecn_enabled {
            return Ok(());
        }

        let counters = self.counters.read().await;

        // Validate ECN counts
        let total_ect = ect0_count + ect1_count + ce_count;
        if total_ect > counters.total_sent {
            // ECN mangling detected
            let mut state = self.state.write().await;
            state.capable = false;
            state.validated = false;
        }

        Ok(())
    }

    /// Handle packet loss (for comparison with ECN)
    pub async fn handle_packet_loss(&self, lost_packets: u64) {
        let mut events = self.congestion_events.lock().await;

        events.push_back(CongestionEvent {
            timestamp: Instant::now(),
            event_type: CongestionEventType::PacketLoss,
            codepoint: EcnCodepoint::NotEct,
            cwnd: 0,
        });

        // Keep event queue bounded
        if events.len() > 100 {
            events.pop_front();
        }
    }

    /// Get recent congestion events
    pub async fn get_congestion_events(&self, max_events: usize) -> Vec<CongestionEvent> {
        let events = self.congestion_events.lock().await;
        events.iter()
            .rev()
            .take(max_events)
            .cloned()
            .collect()
    }
}

/// ECN statistics
#[derive(Debug, Clone)]
pub struct EcnStats {
    pub capable: bool,
    pub validated: bool,
    pub ect0_sent: u64,
    pub ect1_sent: u64,
    pub ce_received: u64,
    pub total_sent: u64,
    pub total_received: u64,
    pub ce_rate: f64,
}

/// Socket-level ECN support
pub mod socket {
    use super::*;
    use std::os::unix::io::RawFd;
    use std::os::raw::{c_int, c_void};

    const IP_TOS: c_int = 1;
    const IPV6_TCLASS: c_int = 67;
    const IP_RECVTOS: c_int = 13;
    const IPV6_RECVTCLASS: c_int = 66;

    /// Set ECN bits on socket
    pub fn set_ecn(fd: RawFd, addr: &SocketAddr, codepoint: EcnCodepoint) -> QuicResult<()> {
        let ecn_bits = codepoint.to_bits() as c_int;

        // Placeholder socket operation - would need proper libc binding
        let result = 0;

        if result < 0 {
            return Err(QuicError::Io(std::io::Error::last_os_error()));
        }

        Ok(())
    }

    /// Enable receiving ECN info
    pub fn enable_ecn_recv(fd: RawFd, addr: &SocketAddr) -> QuicResult<()> {
        let enable: c_int = 1;

        // Placeholder socket operation - would need proper libc binding
        let result = 0;

        if result < 0 {
            return Err(QuicError::Io(std::io::Error::last_os_error()));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecn_codepoint() {
        assert_eq!(EcnCodepoint::from_bits(0b00), EcnCodepoint::NotEct);
        assert_eq!(EcnCodepoint::from_bits(0b10), EcnCodepoint::Ect0);
        assert_eq!(EcnCodepoint::from_bits(0b01), EcnCodepoint::Ect1);
        assert_eq!(EcnCodepoint::from_bits(0b11), EcnCodepoint::Ce);

        assert!(EcnCodepoint::Ect0.is_ect());
        assert!(EcnCodepoint::Ect1.is_ect());
        assert!(!EcnCodepoint::NotEct.is_ect());
        assert!(EcnCodepoint::Ce.is_ce());
    }

    #[tokio::test]
    async fn test_ecn_controller() {
        let config = EcnConfig::default();
        let controller = EcnController::new(config);

        controller.start_negotiation().await.unwrap();

        let marking = controller.get_packet_marking(0).await;
        assert_eq!(marking, EcnCodepoint::NotEct); // Not validated yet

        let stats = controller.get_stats().await;
        assert!(stats.capable);
    }
}