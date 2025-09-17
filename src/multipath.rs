//! Multi-path QUIC Implementation
//!
//! This module provides multi-path QUIC capabilities, allowing a single QUIC connection
//! to utilize multiple network paths simultaneously for improved throughput, reliability,
//! and connection migration support.

use crate::quic::{
    connection::{Connection, ConnectionId},
    error::{QuicError, Result, ProtocolError},
    packet::{Packet, PacketHeader},
};
use crate::udp_mux_advanced::{AdvancedUdpMux, AdvancedMuxConfig};
use bytes::Bytes;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Mutex};
use tokio::time::{timeout, sleep};
use tracing::{debug, info, warn, error, trace};
use serde::{Serialize, Deserialize};

/// Multi-path QUIC connection manager
#[derive(Debug)]
pub struct MultiPathConnection {
    /// Connection identifier
    connection_id: ConnectionId,
    /// Primary path
    primary_path: Arc<RwLock<NetworkPath>>,
    /// Alternative paths
    alternative_paths: Arc<RwLock<HashMap<PathId, NetworkPath>>>,
    /// Path scheduler for packet distribution
    scheduler: Arc<Mutex<PathScheduler>>,
    /// Multi-path configuration
    config: MultiPathConfig,
    /// Path validation state
    path_validator: Arc<RwLock<PathValidator>>,
    /// Statistics and metrics
    stats: Arc<RwLock<MultiPathStats>>,
    /// UDP multiplexer for packet transmission
    udp_mux: Arc<AdvancedUdpMux>,
}

/// Configuration for multi-path QUIC
#[derive(Debug, Clone)]
pub struct MultiPathConfig {
    /// Maximum number of alternative paths
    pub max_alternative_paths: usize,
    /// Path validation timeout
    pub path_validation_timeout: Duration,
    /// Path RTT threshold for path selection
    pub rtt_threshold: Duration,
    /// Enable path migration
    pub enable_path_migration: bool,
    /// Path redundancy factor (0.0 = no redundancy, 1.0 = full redundancy)
    pub redundancy_factor: f64,
    /// Scheduler algorithm
    pub scheduler_algorithm: SchedulerAlgorithm,
    /// Path probing interval
    pub path_probe_interval: Duration,
    /// Maximum packet reordering window
    pub max_reorder_window: usize,
    /// Enable packet duplication for critical packets
    pub enable_packet_duplication: bool,
}

impl Default for MultiPathConfig {
    fn default() -> Self {
        Self {
            max_alternative_paths: 4,
            path_validation_timeout: Duration::from_secs(10),
            rtt_threshold: Duration::from_millis(100),
            enable_path_migration: true,
            redundancy_factor: 0.1,
            scheduler_algorithm: SchedulerAlgorithm::MinRtt,
            path_probe_interval: Duration::from_secs(5),
            max_reorder_window: 100,
            enable_packet_duplication: false,
        }
    }
}

/// Path scheduling algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerAlgorithm {
    /// Round-robin across all paths
    RoundRobin,
    /// Select path with minimum RTT
    MinRtt,
    /// Weighted distribution based on path quality
    Weighted,
    /// Backup path only when primary fails
    Backup,
    /// Redundant transmission across multiple paths
    Redundant,
}

/// Unique identifier for a network path
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathId {
    /// Local address
    local_addr: SocketAddr,
    /// Remote address
    remote_addr: SocketAddr,
    /// Path sequence number
    sequence: u64,
}

impl PathId {
    pub fn new(local_addr: SocketAddr, remote_addr: SocketAddr, sequence: u64) -> Self {
        Self { local_addr, remote_addr, sequence }
    }
}

impl std::fmt::Display for PathId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}->{}#{}", self.local_addr, self.remote_addr, self.sequence)
    }
}

/// Network path information and state
#[derive(Debug, Clone)]
pub struct NetworkPath {
    /// Path identifier
    id: PathId,
    /// Path state
    state: PathState,
    /// RTT statistics
    rtt_stats: RttStats,
    /// Bandwidth estimation
    bandwidth_estimate: BandwidthEstimate,
    /// Congestion window
    congestion_window: u64,
    /// Path validation state
    validation_state: PathValidationState,
    /// Last activity timestamp
    last_activity: Instant,
    /// Packet loss rate
    loss_rate: f64,
    /// Path quality score (0.0 = worst, 1.0 = best)
    quality_score: f64,
}

/// Path states
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathState {
    /// Path is being validated
    Validating,
    /// Path is active and can be used
    Active,
    /// Path is temporarily unavailable
    Standby,
    /// Path has failed validation
    Failed,
    /// Path is being closed
    Closing,
}

/// RTT statistics for a path
#[derive(Debug, Clone)]
pub struct RttStats {
    /// Smoothed RTT
    pub srtt: Duration,
    /// RTT variation
    pub rttvar: Duration,
    /// Minimum RTT observed
    pub min_rtt: Duration,
    /// Latest RTT measurement
    pub latest_rtt: Duration,
}

impl Default for RttStats {
    fn default() -> Self {
        Self {
            srtt: Duration::from_millis(100),
            rttvar: Duration::from_millis(50),
            min_rtt: Duration::from_millis(100),
            latest_rtt: Duration::from_millis(100),
        }
    }
}

/// Bandwidth estimation for a path
#[derive(Debug, Clone)]
pub struct BandwidthEstimate {
    /// Estimated bandwidth in bytes per second
    pub bandwidth_bps: u64,
    /// Last measurement timestamp
    pub last_measurement: Instant,
    /// Measurement confidence (0.0 = no confidence, 1.0 = high confidence)
    pub confidence: f64,
}

impl Default for BandwidthEstimate {
    fn default() -> Self {
        Self {
            bandwidth_bps: 1_000_000, // Default to 1 Mbps
            last_measurement: Instant::now(),
            confidence: 0.5,
        }
    }
}

/// Path validation state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathValidationState {
    /// Not yet validated
    Unvalidated,
    /// Validation in progress
    InProgress(Instant),
    /// Successfully validated
    Validated,
    /// Validation failed
    Failed,
}

/// Path scheduler for packet distribution
#[derive(Debug)]
struct PathScheduler {
    /// Current algorithm
    algorithm: SchedulerAlgorithm,
    /// Round-robin state
    round_robin_index: usize,
    /// Packet sequence for ordering
    next_packet_sequence: u64,
    /// Reordering buffer
    reorder_buffer: VecDeque<ReorderEntry>,
    /// Path weights for weighted scheduling
    path_weights: HashMap<PathId, f64>,
}

/// Entry in the reordering buffer
#[derive(Debug)]
struct ReorderEntry {
    packet_sequence: u64,
    path_id: PathId,
    timestamp: Instant,
    packet_data: Bytes,
}

/// Path validator for managing path validation
#[derive(Debug)]
struct PathValidator {
    /// Paths being validated
    validating_paths: HashMap<PathId, ValidationEntry>,
    /// Validation challenges sent
    challenges: HashMap<PathId, Vec<ValidationChallenge>>,
}

/// Validation entry for a path
#[derive(Debug)]
struct ValidationEntry {
    path: NetworkPath,
    start_time: Instant,
    attempt_count: u32,
}

/// Validation challenge for path validation
#[derive(Debug)]
struct ValidationChallenge {
    challenge_data: [u8; 8],
    sent_time: Instant,
    response_received: bool,
}

/// Multi-path statistics
#[derive(Debug, Default)]
pub struct MultiPathStats {
    /// Total paths created
    pub paths_created: u64,
    /// Active paths count
    pub active_paths: usize,
    /// Failed paths count
    pub failed_paths: u64,
    /// Path migrations count
    pub path_migrations: u64,
    /// Packets sent per path
    pub packets_per_path: HashMap<PathId, u64>,
    /// Bytes sent per path
    pub bytes_per_path: HashMap<PathId, u64>,
    /// Average RTT per path
    pub avg_rtt_per_path: HashMap<PathId, Duration>,
    /// Packet reordering events
    pub reordering_events: u64,
    /// Redundant packets sent
    pub redundant_packets: u64,
}

impl MultiPathConnection {
    /// Create a new multi-path connection
    pub async fn new(
        connection_id: ConnectionId,
        primary_local_addr: SocketAddr,
        primary_remote_addr: SocketAddr,
        config: MultiPathConfig,
        udp_mux: Arc<AdvancedUdpMux>,
    ) -> Result<Self> {
        info!("Creating multi-path connection {} with primary path {}->{}",
              connection_id, primary_local_addr, primary_remote_addr);

        // Create primary path
        let primary_path_id = PathId::new(primary_local_addr, primary_remote_addr, 0);
        let primary_path = NetworkPath {
            id: primary_path_id.clone(),
            state: PathState::Active,
            rtt_stats: RttStats::default(),
            bandwidth_estimate: BandwidthEstimate::default(),
            congestion_window: 10 * 1460, // Initial congestion window
            validation_state: PathValidationState::Validated, // Primary path is pre-validated
            last_activity: Instant::now(),
            loss_rate: 0.0,
            quality_score: 1.0,
        };

        let scheduler = PathScheduler {
            algorithm: config.scheduler_algorithm,
            round_robin_index: 0,
            next_packet_sequence: 0,
            reorder_buffer: VecDeque::new(),
            path_weights: HashMap::new(),
        };

        let path_validator = PathValidator {
            validating_paths: HashMap::new(),
            challenges: HashMap::new(),
        };

        let multipath_conn = Self {
            connection_id,
            primary_path: Arc::new(RwLock::new(primary_path)),
            alternative_paths: Arc::new(RwLock::new(HashMap::new())),
            scheduler: Arc::new(Mutex::new(scheduler)),
            config,
            path_validator: Arc::new(RwLock::new(path_validator)),
            stats: Arc::new(RwLock::new(MultiPathStats::default())),
            udp_mux,
        };

        Ok(multipath_conn)
    }

    /// Add an alternative network path
    pub async fn add_path(
        &self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Result<PathId> {
        let mut alt_paths = self.alternative_paths.write().await;

        if alt_paths.len() >= self.config.max_alternative_paths {
            return Err(QuicError::Protocol(ProtocolError::InvalidState(
                "Maximum alternative paths exceeded".to_string()
            )));
        }

        let sequence = alt_paths.len() as u64 + 1;
        let path_id = PathId::new(local_addr, remote_addr, sequence);

        let path = NetworkPath {
            id: path_id.clone(),
            state: PathState::Validating,
            rtt_stats: RttStats::default(),
            bandwidth_estimate: BandwidthEstimate::default(),
            congestion_window: 10 * 1460,
            validation_state: PathValidationState::Unvalidated,
            last_activity: Instant::now(),
            loss_rate: 0.0,
            quality_score: 0.5, // Start with medium quality
        };

        alt_paths.insert(path_id.clone(), path);

        // Start path validation
        self.start_path_validation(&path_id).await?;

        info!("Added alternative path: {}", path_id);

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.paths_created += 1;
        }

        Ok(path_id)
    }

    /// Start path validation for a path
    async fn start_path_validation(&self, path_id: &PathId) -> Result<()> {
        debug!("Starting path validation for path: {}", path_id);

        let mut validator = self.path_validator.write().await;

        // Create validation entry
        let path = {
            if path_id.sequence == 0 {
                // Primary path
                self.primary_path.read().await.clone()
            } else {
                // Alternative path
                let alt_paths = self.alternative_paths.read().await;
                alt_paths.get(path_id).cloned()
                    .ok_or_else(|| QuicError::Protocol(ProtocolError::InvalidState(
                        "Path not found".to_string()
                    )))?
            }
        };

        let validation_entry = ValidationEntry {
            path,
            start_time: Instant::now(),
            attempt_count: 1,
        };

        validator.validating_paths.insert(path_id.clone(), validation_entry);

        // Send path challenge
        self.send_path_challenge(path_id).await?;

        Ok(())
    }

    /// Send path challenge for validation
    async fn send_path_challenge(&self, path_id: &PathId) -> Result<()> {
        debug!("Sending path challenge for path: {}", path_id);

        // Generate random challenge data
        let mut challenge_data = [0u8; 8];
        // In a real implementation, this would use proper cryptographic randomness
        for (i, byte) in challenge_data.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(37);
        }

        let challenge = ValidationChallenge {
            challenge_data,
            sent_time: Instant::now(),
            response_received: false,
        };

        // Store challenge
        {
            let mut validator = self.path_validator.write().await;
            validator.challenges.entry(path_id.clone())
                .or_insert_with(Vec::new)
                .push(challenge);
        }

        // Build and send PATH_CHALLENGE frame
        let challenge_packet = self.build_path_challenge_packet(&challenge_data, path_id).await?;

        self.udp_mux.send_packet(challenge_packet, path_id.remote_addr).await?;

        Ok(())
    }

    /// Build PATH_CHALLENGE packet
    async fn build_path_challenge_packet(
        &self,
        challenge_data: &[u8; 8],
        path_id: &PathId,
    ) -> Result<Bytes> {
        // This is a simplified packet construction
        // In a real implementation, this would build a proper QUIC packet with PATH_CHALLENGE frame

        let mut packet = Vec::new();

        // Short header (simplified)
        packet.push(0x40);

        // Connection ID (8 bytes for simplicity)
        packet.extend_from_slice(&self.connection_id.as_bytes()[..8.min(self.connection_id.as_bytes().len())]);
        if self.connection_id.as_bytes().len() < 8 {
            packet.resize(9, 0); // Pad to ensure 8 bytes
        }

        // Packet number (simplified - just use 1)
        packet.extend_from_slice(&[0, 0, 0, 1]);

        // PATH_CHALLENGE frame
        packet.push(0x1a); // PATH_CHALLENGE frame type
        packet.extend_from_slice(challenge_data);

        Ok(Bytes::from(packet))
    }

    /// Send packet using multi-path scheduling
    pub async fn send_packet(&self, packet_data: Bytes) -> Result<()> {
        let path_id = self.schedule_packet(&packet_data).await?;

        // Get path information
        let remote_addr = if path_id.sequence == 0 {
            // Primary path
            let primary = self.primary_path.read().await;
            primary.id.remote_addr
        } else {
            // Alternative path
            let alt_paths = self.alternative_paths.read().await;
            alt_paths.get(&path_id)
                .map(|p| p.id.remote_addr)
                .ok_or_else(|| QuicError::Protocol(ProtocolError::InvalidState(
                    "Path not found".to_string()
                )))?
        };

        // Send packet
        self.udp_mux.send_packet(packet_data.clone(), remote_addr).await?;

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            *stats.packets_per_path.entry(path_id.clone()).or_insert(0) += 1;
            *stats.bytes_per_path.entry(path_id.clone()).or_insert(0) += packet_data.len() as u64;
        }

        // Handle packet duplication for critical packets
        if self.config.enable_packet_duplication && self.is_critical_packet(&packet_data) {
            if let Some(backup_path_id) = self.select_backup_path(&path_id).await {
                let backup_remote_addr = if backup_path_id.sequence == 0 {
                    let primary = self.primary_path.read().await;
                    primary.id.remote_addr
                } else {
                    let alt_paths = self.alternative_paths.read().await;
                    alt_paths.get(&backup_path_id)
                        .map(|p| p.id.remote_addr)
                        .unwrap_or(remote_addr)
                };

                // Send duplicate on backup path
                self.udp_mux.send_packet(packet_data, backup_remote_addr).await?;

                let mut stats = self.stats.write().await;
                stats.redundant_packets += 1;
            }
        }

        Ok(())
    }

    /// Schedule packet to appropriate path
    async fn schedule_packet(&self, packet_data: &Bytes) -> Result<PathId> {
        let mut scheduler = self.scheduler.lock().await;

        match scheduler.algorithm {
            SchedulerAlgorithm::RoundRobin => {
                self.schedule_round_robin(&mut scheduler).await
            },
            SchedulerAlgorithm::MinRtt => {
                self.schedule_min_rtt().await
            },
            SchedulerAlgorithm::Weighted => {
                self.schedule_weighted(&mut scheduler).await
            },
            SchedulerAlgorithm::Backup => {
                self.schedule_backup().await
            },
            SchedulerAlgorithm::Redundant => {
                self.schedule_redundant(&mut scheduler).await
            },
        }
    }

    /// Round-robin scheduling
    async fn schedule_round_robin(&self, scheduler: &mut PathScheduler) -> Result<PathId> {
        let active_paths = self.get_active_paths().await;

        if active_paths.is_empty() {
            return Err(QuicError::Protocol(ProtocolError::InvalidState(
                "No active paths available".to_string()
            )));
        }

        let selected_index = scheduler.round_robin_index % active_paths.len();
        scheduler.round_robin_index += 1;

        Ok(active_paths[selected_index].clone())
    }

    /// Minimum RTT scheduling
    async fn schedule_min_rtt(&self) -> Result<PathId> {
        let active_paths = self.get_active_paths().await;

        if active_paths.is_empty() {
            return Err(QuicError::Protocol(ProtocolError::InvalidState(
                "No active paths available".to_string()
            )));
        }

        // Find path with minimum RTT
        let mut min_rtt = Duration::from_secs(3600);
        let mut best_path_id = active_paths[0].clone();

        for path_id in &active_paths {
            let rtt = self.get_path_rtt(path_id).await;
            if rtt < min_rtt {
                min_rtt = rtt;
                best_path_id = path_id.clone();
            }
        }

        Ok(best_path_id)
    }

    /// Weighted scheduling
    async fn schedule_weighted(&self, scheduler: &mut PathScheduler) -> Result<PathId> {
        let active_paths = self.get_active_paths().await;

        if active_paths.is_empty() {
            return Err(QuicError::Protocol(ProtocolError::InvalidState(
                "No active paths available".to_string()
            )));
        }

        // Select based on quality scores as weights
        let mut total_weight = 0.0;
        let mut weights = Vec::new();

        for path_id in &active_paths {
            let quality = self.get_path_quality(path_id).await;
            weights.push(quality);
            total_weight += quality;
        }

        if total_weight <= 0.0 {
            // Fallback to round-robin
            return self.schedule_round_robin(scheduler).await;
        }

        // Simple weighted selection (would use proper random selection in real implementation)
        let selection_point = (scheduler.round_robin_index % 100) as f64 / 100.0 * total_weight;
        scheduler.round_robin_index += 1;

        let mut cumulative_weight = 0.0;
        for (i, weight) in weights.iter().enumerate() {
            cumulative_weight += weight;
            if selection_point <= cumulative_weight {
                return Ok(active_paths[i].clone());
            }
        }

        // Fallback to first path
        Ok(active_paths[0].clone())
    }

    /// Backup scheduling (primary only, alternatives as backup)
    async fn schedule_backup(&self) -> Result<PathId> {
        // Always try primary path first
        let primary_path = self.primary_path.read().await;
        if primary_path.state == PathState::Active {
            return Ok(primary_path.id.clone());
        }

        // Fall back to best alternative
        let active_paths = self.get_active_paths().await;
        for path_id in &active_paths {
            if path_id.sequence != 0 { // Not primary
                return Ok(path_id.clone());
            }
        }

        Err(QuicError::Protocol(ProtocolError::InvalidState(
            "No active paths available".to_string()
        )))
    }

    /// Redundant scheduling (send on multiple paths)
    async fn schedule_redundant(&self, scheduler: &mut PathScheduler) -> Result<PathId> {
        // For redundant scheduling, we'll return the primary path
        // The caller should handle sending on multiple paths
        let primary_path = self.primary_path.read().await;
        Ok(primary_path.id.clone())
    }

    /// Get all active paths
    async fn get_active_paths(&self) -> Vec<PathId> {
        let mut active_paths = Vec::new();

        // Check primary path
        {
            let primary = self.primary_path.read().await;
            if primary.state == PathState::Active {
                active_paths.push(primary.id.clone());
            }
        }

        // Check alternative paths
        {
            let alt_paths = self.alternative_paths.read().await;
            for path in alt_paths.values() {
                if path.state == PathState::Active {
                    active_paths.push(path.id.clone());
                }
            }
        }

        active_paths
    }

    /// Get RTT for a specific path
    async fn get_path_rtt(&self, path_id: &PathId) -> Duration {
        if path_id.sequence == 0 {
            let primary = self.primary_path.read().await;
            primary.rtt_stats.srtt
        } else {
            let alt_paths = self.alternative_paths.read().await;
            alt_paths.get(path_id)
                .map(|p| p.rtt_stats.srtt)
                .unwrap_or(Duration::from_secs(1))
        }
    }

    /// Get quality score for a specific path
    async fn get_path_quality(&self, path_id: &PathId) -> f64 {
        if path_id.sequence == 0 {
            let primary = self.primary_path.read().await;
            primary.quality_score
        } else {
            let alt_paths = self.alternative_paths.read().await;
            alt_paths.get(path_id)
                .map(|p| p.quality_score)
                .unwrap_or(0.1)
        }
    }

    /// Check if packet is critical (requires duplication)
    fn is_critical_packet(&self, _packet_data: &Bytes) -> bool {
        // In a real implementation, this would analyze the packet content
        // to determine if it contains critical frames (e.g., handshake, connection close)
        false
    }

    /// Select backup path for packet duplication
    async fn select_backup_path(&self, primary_path_id: &PathId) -> Option<PathId> {
        let active_paths = self.get_active_paths().await;

        // Find first active path that's different from the primary
        for path_id in &active_paths {
            if path_id != primary_path_id {
                return Some(path_id.clone());
            }
        }

        None
    }

    /// Get multi-path statistics
    pub async fn stats(&self) -> MultiPathStats {
        let stats = self.stats.read().await;
        let mut result = stats.clone();

        // Update active paths count
        result.active_paths = self.get_active_paths().await.len();

        result
    }

    /// Remove a path
    pub async fn remove_path(&self, path_id: &PathId) -> Result<()> {
        if path_id.sequence == 0 {
            return Err(QuicError::Protocol(ProtocolError::InvalidState(
                "Cannot remove primary path".to_string()
            )));
        }

        let mut alt_paths = self.alternative_paths.write().await;
        alt_paths.remove(path_id);

        // Clean up validation state
        {
            let mut validator = self.path_validator.write().await;
            validator.validating_paths.remove(path_id);
            validator.challenges.remove(path_id);
        }

        info!("Removed path: {}", path_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::udp_mux_advanced::AdvancedMuxConfig;

    #[tokio::test]
    async fn test_multipath_creation() {
        let connection_id = ConnectionId::new(vec![1, 2, 3, 4]);
        let config = MultiPathConfig::default();
        let mux_config = AdvancedMuxConfig::default();

        let primary_addr = "127.0.0.1:0".parse().unwrap();
        let udp_mux = Arc::new(
            AdvancedUdpMux::new(primary_addr, vec![], mux_config).await.unwrap()
        );

        let local_addr = "127.0.0.1:8000".parse().unwrap();
        let remote_addr = "127.0.0.1:8001".parse().unwrap();

        let multipath = MultiPathConnection::new(
            connection_id,
            local_addr,
            remote_addr,
            config,
            udp_mux,
        ).await;

        assert!(multipath.is_ok());
    }

    #[tokio::test]
    async fn test_path_management() {
        let connection_id = ConnectionId::new(vec![1, 2, 3, 4]);
        let config = MultiPathConfig::default();
        let mux_config = AdvancedMuxConfig::default();

        let primary_addr = "127.0.0.1:0".parse().unwrap();
        let udp_mux = Arc::new(
            AdvancedUdpMux::new(primary_addr, vec![], mux_config).await.unwrap()
        );

        let local_addr = "127.0.0.1:8000".parse().unwrap();
        let remote_addr = "127.0.0.1:8001".parse().unwrap();

        let multipath = MultiPathConnection::new(
            connection_id,
            local_addr,
            remote_addr,
            config,
            udp_mux,
        ).await.unwrap();

        // Add alternative path
        let alt_local = "127.0.0.1:8002".parse().unwrap();
        let alt_remote = "127.0.0.1:8003".parse().unwrap();

        let path_id = multipath.add_path(alt_local, alt_remote).await.unwrap();
        assert_eq!(path_id.sequence, 1);

        // Remove path
        let result = multipath.remove_path(&path_id).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_path_id() {
        let local_addr = "127.0.0.1:8000".parse().unwrap();
        let remote_addr = "127.0.0.1:8001".parse().unwrap();
        let path_id = PathId::new(local_addr, remote_addr, 1);

        assert_eq!(path_id.local_addr, local_addr);
        assert_eq!(path_id.remote_addr, remote_addr);
        assert_eq!(path_id.sequence, 1);
    }
}