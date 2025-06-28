use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Mutex};
use tracing::{debug, info, warn, error};

use super::{ConnectionId, packet::PacketNumber, error::{QuicError, Result}};

/// Connection migration manager for handling network changes
#[derive(Debug)]
pub struct MigrationManager {
    /// Current active path
    active_path: Arc<RwLock<NetworkPath>>,
    /// Alternative paths being validated
    pending_paths: Arc<RwLock<HashMap<SocketAddr, PathValidation>>>,
    /// Path validation state
    path_challenges: Arc<RwLock<HashMap<[u8; 8], PathChallenge>>>,
    /// Migration configuration
    config: MigrationConfig,
    /// Migration statistics
    stats: Arc<Mutex<MigrationStats>>,
}

#[derive(Debug, Clone)]
pub struct MigrationConfig {
    /// Enable connection migration
    pub enable_migration: bool,
    /// Maximum number of concurrent path validations
    pub max_concurrent_validations: usize,
    /// Path validation timeout
    pub validation_timeout: Duration,
    /// Minimum time between migration attempts
    pub migration_cooldown: Duration,
    /// Enable path MTU discovery
    pub enable_pmtu_discovery: bool,
    /// Preferred address validation timeout
    pub preferred_address_timeout: Duration,
}

impl Default for MigrationConfig {
    fn default() -> Self {
        Self {
            enable_migration: true,
            max_concurrent_validations: 3,
            validation_timeout: Duration::from_secs(30),
            migration_cooldown: Duration::from_secs(5),
            enable_pmtu_discovery: true,
            preferred_address_timeout: Duration::from_secs(10),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NetworkPath {
    /// Local address
    pub local_addr: SocketAddr,
    /// Remote address  
    pub remote_addr: SocketAddr,
    /// Path MTU
    pub mtu: u16,
    /// Round-trip time on this path
    pub rtt: Option<Duration>,
    /// Path quality score (0-100)
    pub quality_score: u8,
    /// Last activity timestamp
    pub last_activity: Instant,
    /// Bytes sent on this path
    pub bytes_sent: u64,
    /// Bytes received on this path
    pub bytes_received: u64,
    /// Packet loss rate on this path
    pub loss_rate: f64,
}

#[derive(Debug)]
struct PathValidation {
    remote_addr: SocketAddr,
    challenge_data: [u8; 8],
    start_time: Instant,
    retry_count: u32,
    validated: bool,
}

#[derive(Debug)]
struct PathChallenge {
    challenge_data: [u8; 8],
    path_addr: SocketAddr,
    sent_time: Instant,
    connection_id: ConnectionId,
}

#[derive(Debug, Default, Clone)]
pub struct MigrationStats {
    pub migrations_attempted: u64,
    pub migrations_successful: u64,
    pub migrations_failed: u64,
    pub paths_validated: u64,
    pub path_validations_failed: u64,
    pub preferred_address_migrations: u64,
}

impl MigrationManager {
    pub fn new(initial_path: NetworkPath, config: MigrationConfig) -> Self {
        Self {
            active_path: Arc::new(RwLock::new(initial_path)),
            pending_paths: Arc::new(RwLock::new(HashMap::new())),
            path_challenges: Arc::new(RwLock::new(HashMap::new())),
            config,
            stats: Arc::new(Mutex::new(MigrationStats::default())),
        }
    }

    /// Initiate connection migration to new address
    pub async fn initiate_migration(&self, new_remote_addr: SocketAddr) -> Result<()> {
        if !self.config.enable_migration {
            return Err(QuicError::Config("Migration disabled".to_string()));
        }

        let active_path = self.active_path.read().await;
        
        // Check cooldown period
        if active_path.last_activity.elapsed() < self.config.migration_cooldown {
            return Err(QuicError::Config(
                "Migration attempted too soon after last migration".to_string()
            ));
        }

        // Check if we're already validating this path
        let pending_paths = self.pending_paths.read().await;
        if pending_paths.contains_key(&new_remote_addr) {
            debug!("Path validation already in progress for {}", new_remote_addr);
            return Ok(());
        }

        // Check concurrent validation limit
        if pending_paths.len() >= self.config.max_concurrent_validations {
            return Err(QuicError::Config("Too many concurrent path validations".to_string()));
        }

        drop(pending_paths);
        drop(active_path);

        // Start path validation
        self.start_path_validation(new_remote_addr).await?;

        let mut stats = self.stats.lock().await;
        stats.migrations_attempted += 1;

        info!("Initiated connection migration to {}", new_remote_addr);
        Ok(())
    }

    /// Start path validation for a new address
    async fn start_path_validation(&self, remote_addr: SocketAddr) -> Result<()> {
        let challenge_data = self.generate_path_challenge();
        
        let validation = PathValidation {
            remote_addr,
            challenge_data,
            start_time: Instant::now(),
            retry_count: 0,
            validated: false,
        };

        let mut pending_paths = self.pending_paths.write().await;
        pending_paths.insert(remote_addr, validation);

        // Store challenge for response validation
        let challenge = PathChallenge {
            challenge_data,
            path_addr: remote_addr,
            sent_time: Instant::now(),
            connection_id: ConnectionId::new(), // Would use actual connection ID
        };

        let mut challenges = self.path_challenges.write().await;
        challenges.insert(challenge_data, challenge);

        debug!("Started path validation for {} with challenge {:?}", 
               remote_addr, challenge_data);

        Ok(())
    }

    /// Process path challenge frame
    pub async fn on_path_challenge(&self, challenge_data: [u8; 8], from_addr: SocketAddr) -> Result<[u8; 8]> {
        debug!("Received path challenge from {}: {:?}", from_addr, challenge_data);
        
        // Generate response data (echo back the challenge)
        Ok(challenge_data)
    }

    /// Process path response frame
    pub async fn on_path_response(&self, response_data: [u8; 8], from_addr: SocketAddr) -> Result<()> {
        let mut challenges = self.path_challenges.write().await;
        
        if let Some(challenge) = challenges.remove(&response_data) {
            if challenge.path_addr == from_addr {
                // Valid response - mark path as validated
                let mut pending_paths = self.pending_paths.write().await;
                
                if let Some(validation) = pending_paths.get_mut(&from_addr) {
                    validation.validated = true;
                    
                    let rtt = challenge.sent_time.elapsed();
                    info!("Path validated for {} (RTT: {:?})", from_addr, rtt);
                    
                    // If this is a better path, migrate to it
                    if self.should_migrate_to_path(from_addr, rtt).await? {
                        self.complete_migration(from_addr, rtt).await?;
                    }
                    
                    let mut stats = self.stats.lock().await;
                    stats.paths_validated += 1;
                } else {
                    warn!("Path validation completed but no pending validation found for {}", from_addr);
                }
            } else {
                warn!("Path response received from unexpected address: expected {}, got {}", 
                      challenge.path_addr, from_addr);
            }
        } else {
            debug!("Unknown path response from {}: {:?}", from_addr, response_data);
        }

        Ok(())
    }

    /// Check if we should migrate to the validated path
    async fn should_migrate_to_path(&self, path_addr: SocketAddr, rtt: Duration) -> Result<bool> {
        let active_path = self.active_path.read().await;
        
        // Simple migration decision based on RTT improvement
        if let Some(current_rtt) = active_path.rtt {
            // Migrate if new path has significantly better RTT (>20% improvement)
            let improvement_threshold = current_rtt.as_millis() as f64 * 0.8;
            if (rtt.as_millis() as f64) < improvement_threshold {
                return Ok(true);
            }
        } else {
            // No RTT data for current path, migrate
            return Ok(true);
        }

        // Other migration triggers could include:
        // - Current path showing high loss rate
        // - Current path becoming unavailable
        // - Explicit user request (e.g., WiFi to cellular)
        
        Ok(false)
    }

    /// Complete migration to validated path
    async fn complete_migration(&self, new_remote_addr: SocketAddr, rtt: Duration) -> Result<()> {
        let mut active_path = self.active_path.write().await;
        let mut pending_paths = self.pending_paths.write().await;
        
        // Remove from pending validations
        pending_paths.remove(&new_remote_addr);
        
        // Create new path
        let new_path = NetworkPath {
            local_addr: active_path.local_addr, // Keep same local address
            remote_addr: new_remote_addr,
            mtu: 1200, // Start with conservative MTU
            rtt: Some(rtt),
            quality_score: 80, // Initial quality score
            last_activity: Instant::now(),
            bytes_sent: 0,
            bytes_received: 0,
            loss_rate: 0.0,
        };

        let old_remote = active_path.remote_addr;
        *active_path = new_path;

        let mut stats = self.stats.lock().await;
        stats.migrations_successful += 1;

        info!("Migration completed: {} -> {}", old_remote, new_remote_addr);
        Ok(())
    }

    /// Handle preferred address from server
    pub async fn handle_preferred_address(&self, preferred_addr: SocketAddr) -> Result<()> {
        info!("Server suggested preferred address: {}", preferred_addr);
        
        // Validate the preferred address
        self.start_path_validation(preferred_addr).await?;
        
        let mut stats = self.stats.lock().await;
        stats.preferred_address_migrations += 1;
        
        Ok(())
    }

    /// Get current active path
    pub async fn get_active_path(&self) -> NetworkPath {
        self.active_path.read().await.clone()
    }

    /// Update path statistics
    pub async fn update_path_stats(&self, bytes_sent: u64, bytes_received: u64, loss_rate: f64) {
        let mut active_path = self.active_path.write().await;
        active_path.bytes_sent += bytes_sent;
        active_path.bytes_received += bytes_received;
        active_path.loss_rate = loss_rate;
        active_path.last_activity = Instant::now();
        
        // Update quality score based on performance
        active_path.quality_score = self.calculate_quality_score(loss_rate, active_path.rtt);
    }

    /// Calculate path quality score
    fn calculate_quality_score(&self, loss_rate: f64, rtt: Option<Duration>) -> u8 {
        let mut score = 100u8;
        
        // Penalize for packet loss
        score = score.saturating_sub((loss_rate * 100.0) as u8);
        
        // Penalize for high RTT
        if let Some(rtt) = rtt {
            let rtt_ms = rtt.as_millis() as u8;
            if rtt_ms > 100 {
                score = score.saturating_sub(rtt_ms - 100);
            }
        }
        
        score.max(10) // Minimum score of 10
    }

    /// Cleanup expired path validations
    pub async fn cleanup_expired_validations(&self) {
        let mut pending_paths = self.pending_paths.write().await;
        let mut challenges = self.path_challenges.write().await;
        let now = Instant::now();
        
        // Remove expired validations
        pending_paths.retain(|addr, validation| {
            let expired = now.duration_since(validation.start_time) > self.config.validation_timeout;
            if expired {
                debug!("Path validation expired for {}", addr);
                // Also remove associated challenge
                challenges.remove(&validation.challenge_data);
            }
            !expired
        });
        
        // Update stats for failed validations
        let mut stats = self.stats.lock().await;
        let expired_count = pending_paths.len();
        stats.path_validations_failed += expired_count as u64;
    }

    /// Generate random path challenge data
    fn generate_path_challenge(&self) -> [u8; 8] {
        let mut challenge = [0u8; 8];
        for i in 0..8 {
            challenge[i] = rand::random();
        }
        challenge
    }

    /// Probe path MTU for active path
    pub async fn probe_path_mtu(&self) -> Result<u16> {
        if !self.config.enable_pmtu_discovery {
            return Ok(1200); // Conservative default
        }

        let active_path = self.active_path.read().await;
        let current_mtu = active_path.mtu;
        
        // Simple PMTU discovery - try larger packets
        let probe_sizes = [1500, 9000]; // Ethernet, Jumbo frames
        
        for &probe_size in &probe_sizes {
            if probe_size > current_mtu {
                // Would send PATH_CHALLENGE with large packet
                // For now, just return current MTU
                debug!("PMTU probe for {} bytes (current: {})", probe_size, current_mtu);
                break;
            }
        }
        
        Ok(current_mtu)
    }

    /// Get migration statistics
    pub async fn get_stats(&self) -> MigrationStats {
        self.stats.lock().await.clone()
    }

    /// Force migration (for testing or manual triggers)
    pub async fn force_migration(&self, new_remote_addr: SocketAddr) -> Result<()> {
        let rtt = Duration::from_millis(50); // Assume reasonable RTT
        self.complete_migration(new_remote_addr, rtt).await
    }

    /// Check if migration is available
    pub fn is_migration_enabled(&self) -> bool {
        self.config.enable_migration
    }

    /// Get pending path validations
    pub async fn get_pending_validations(&self) -> Vec<SocketAddr> {
        self.pending_paths.read().await.keys().cloned().collect()
    }
}

/// Mobile-specific migration triggers
pub struct MobileMigrationTrigger {
    manager: Arc<MigrationManager>,
    network_monitor: NetworkMonitor,
}

#[derive(Debug)]
struct NetworkMonitor {
    current_network: NetworkType,
    signal_strength: u8, // 0-100
    last_check: Instant,
}

#[derive(Debug, Clone, PartialEq)]
enum NetworkType {
    WiFi,
    Cellular4G,
    Cellular5G,
    Ethernet,
    Unknown,
}

impl MobileMigrationTrigger {
    pub fn new(manager: Arc<MigrationManager>) -> Self {
        Self {
            manager,
            network_monitor: NetworkMonitor {
                current_network: NetworkType::Unknown,
                signal_strength: 100,
                last_check: Instant::now(),
            },
        }
    }

    /// Simulate network change detection
    pub async fn check_network_changes(&mut self) -> Result<()> {
        // In a real implementation, this would interface with:
        // - Android NetworkCallback
        // - iOS Network Framework
        // - Linux NetworkManager
        // - Windows WinRT APIs
        
        let new_network = self.detect_current_network().await;
        
        if new_network != self.network_monitor.current_network {
            info!("Network change detected: {:?} -> {:?}", 
                  self.network_monitor.current_network, new_network);
            
            // Trigger migration if needed
            match new_network {
                NetworkType::WiFi => {
                    // WiFi usually has better characteristics
                    if let Ok(new_addr) = self.get_wifi_address().await {
                        self.manager.initiate_migration(new_addr).await?;
                    }
                }
                NetworkType::Cellular5G => {
                    // 5G might be better than 4G
                    if self.network_monitor.current_network == NetworkType::Cellular4G {
                        if let Ok(new_addr) = self.get_cellular_address().await {
                            self.manager.initiate_migration(new_addr).await?;
                        }
                    }
                }
                _ => {}
            }
            
            self.network_monitor.current_network = new_network;
        }
        
        Ok(())
    }

    async fn detect_current_network(&self) -> NetworkType {
        // Simplified network detection
        // Real implementation would check system APIs
        NetworkType::WiFi
    }

    async fn get_wifi_address(&self) -> Result<SocketAddr> {
        // Would get actual WiFi interface address
        Ok("192.168.1.100:0".parse().unwrap())
    }

    async fn get_cellular_address(&self) -> Result<SocketAddr> {
        // Would get actual cellular interface address
        Ok("10.0.0.100:0".parse().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_path_validation() {
        let initial_path = NetworkPath {
            local_addr: "127.0.0.1:12345".parse().unwrap(),
            remote_addr: "127.0.0.1:54321".parse().unwrap(),
            mtu: 1200,
            rtt: Some(Duration::from_millis(50)),
            quality_score: 90,
            last_activity: Instant::now(),
            bytes_sent: 0,
            bytes_received: 0,
            loss_rate: 0.0,
        };

        let manager = MigrationManager::new(initial_path, MigrationConfig::default());
        let new_addr = "127.0.0.1:55555".parse().unwrap();

        // Start migration
        manager.initiate_migration(new_addr).await.unwrap();

        // Check that validation was started
        let pending = manager.get_pending_validations().await;
        assert!(pending.contains(&new_addr));
    }

    #[tokio::test]
    async fn test_path_challenge_response() {
        let initial_path = NetworkPath {
            local_addr: "127.0.0.1:12345".parse().unwrap(),
            remote_addr: "127.0.0.1:54321".parse().unwrap(),
            mtu: 1200,
            rtt: None,
            quality_score: 50,
            last_activity: Instant::now(),
            bytes_sent: 0,
            bytes_received: 0,
            loss_rate: 0.1,
        };

        let manager = MigrationManager::new(initial_path, MigrationConfig::default());
        let challenge_data = [1, 2, 3, 4, 5, 6, 7, 8];
        let from_addr = "127.0.0.1:55555".parse().unwrap();

        // Process challenge
        let response = manager.on_path_challenge(challenge_data, from_addr).await.unwrap();
        assert_eq!(response, challenge_data);
    }
}