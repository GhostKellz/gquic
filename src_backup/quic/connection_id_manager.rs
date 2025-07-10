use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Mutex};
use tracing::{debug, info, warn, error};
use rand::{Rng, thread_rng, RngCore};

use super::{ConnectionId, frame::Frame, error::{QuicError, Result}};

/// Connection ID manager for privacy and network path changes
/// Critical for crypto applications to prevent tracking and correlation
#[derive(Debug)]
pub struct ConnectionIdManager {
    /// Currently active connection IDs
    active_connection_ids: Arc<RwLock<HashMap<u64, ConnectionIdInfo>>>,
    /// Connection IDs pending retirement
    retiring_connection_ids: Arc<RwLock<HashMap<u64, RetiringConnectionId>>>,
    /// Connection ID generation state
    generator: Arc<Mutex<ConnectionIdGenerator>>,
    /// Configuration
    config: ConnectionIdConfig,
    /// Statistics
    stats: Arc<Mutex<ConnectionIdStats>>,
    /// Current primary connection ID
    primary_connection_id: Arc<RwLock<Option<ConnectionId>>>,
}

#[derive(Debug, Clone)]
pub struct ConnectionIdConfig {
    /// Enable connection ID rotation
    pub enable_rotation: bool,
    /// Connection ID length (4-18 bytes as per RFC)
    pub connection_id_length: usize,
    /// Maximum number of active connection IDs
    pub max_active_connection_ids: usize,
    /// Rotation interval
    pub rotation_interval: Duration,
    /// Minimum lifetime before retirement
    pub min_lifetime: Duration,
    /// Enable privacy protection features
    pub enable_privacy_protection: bool,
    /// Stateless reset token length
    pub stateless_reset_token_length: usize,
}

impl Default for ConnectionIdConfig {
    fn default() -> Self {
        Self {
            enable_rotation: true,
            connection_id_length: 8, // Common length
            max_active_connection_ids: 8,
            rotation_interval: Duration::from_secs(300), // 5 minutes
            min_lifetime: Duration::from_secs(60), // 1 minute minimum
            enable_privacy_protection: true,
            stateless_reset_token_length: 16,
        }
    }
}

#[derive(Debug, Clone)]
struct ConnectionIdInfo {
    connection_id: ConnectionId,
    sequence_number: u64,
    stateless_reset_token: Option<[u8; 16]>,
    created_at: Instant,
    last_used: Instant,
    is_primary: bool,
    retire_prior_to: Option<u64>,
}

#[derive(Debug)]
struct RetiringConnectionId {
    connection_id: ConnectionId,
    sequence_number: u64,
    retirement_time: Instant,
    reason: RetirementReason,
}

#[derive(Debug, Clone)]
enum RetirementReason {
    Rotation,
    PathChange,
    Security,
    Manual,
}

#[derive(Debug)]
struct ConnectionIdGenerator {
    next_sequence_number: u64,
    secret_key: [u8; 32],
    last_generation_time: Instant,
}

#[derive(Debug, Default, Clone)]
struct ConnectionIdStats {
    connection_ids_generated: u64,
    connection_ids_retired: u64,
    rotations_performed: u64,
    privacy_violations_detected: u64,
    stateless_resets_sent: u64,
    invalid_connection_ids_received: u64,
}

impl ConnectionIdManager {
    pub fn new(config: ConnectionIdConfig) -> Self {
        let mut secret_key = [0u8; 32];
        thread_rng().fill_bytes(&mut secret_key);

        Self {
            active_connection_ids: Arc::new(RwLock::new(HashMap::new())),
            retiring_connection_ids: Arc::new(RwLock::new(HashMap::new())),
            generator: Arc::new(Mutex::new(ConnectionIdGenerator {
                next_sequence_number: 0,
                secret_key,
                last_generation_time: Instant::now(),
            })),
            config,
            stats: Arc::new(Mutex::new(ConnectionIdStats::default())),
            primary_connection_id: Arc::new(RwLock::new(None)),
        }
    }

    /// Generate a new connection ID
    pub async fn generate_connection_id(&self) -> Result<(ConnectionId, u64, Option<[u8; 16]>)> {
        let mut generator = self.generator.lock().await;
        let sequence_number = generator.next_sequence_number;
        generator.next_sequence_number += 1;
        generator.last_generation_time = Instant::now();

        // Generate cryptographically random connection ID
        let mut id_bytes = vec![0u8; self.config.connection_id_length];
        thread_rng().fill_bytes(&mut id_bytes[..]);

        // Add entropy from secret key and sequence number
        let entropy = self.derive_entropy(&generator.secret_key, sequence_number);
        for (i, &entropy_byte) in entropy.iter().enumerate() {
            if i < id_bytes.len() {
                id_bytes[i] ^= entropy_byte;
            }
        }

        let connection_id = ConnectionId::from_bytes(&id_bytes);

        // Generate stateless reset token
        let stateless_reset_token = if self.config.enable_privacy_protection {
            Some(self.generate_stateless_reset_token(&connection_id, &generator.secret_key))
        } else {
            None
        };

        // Store connection ID info
        let connection_id_info = ConnectionIdInfo {
            connection_id: connection_id.clone(),
            sequence_number,
            stateless_reset_token,
            created_at: Instant::now(),
            last_used: Instant::now(),
            is_primary: false,
            retire_prior_to: None,
        };

        let mut active_ids = self.active_connection_ids.write().await;
        active_ids.insert(sequence_number, connection_id_info);

        // Update statistics
        let mut stats = self.stats.lock().await;
        stats.connection_ids_generated += 1;

        debug!("Generated connection ID {} with sequence {}", 
               connection_id, sequence_number);

        Ok((connection_id, sequence_number, stateless_reset_token))
    }

    /// Set the primary connection ID
    pub async fn set_primary_connection_id(&self, connection_id: ConnectionId) -> Result<()> {
        let mut active_ids = self.active_connection_ids.write().await;
        
        // Mark all as non-primary
        for info in active_ids.values_mut() {
            info.is_primary = false;
        }

        // Find and mark the new primary
        if let Some(info) = active_ids.values_mut().find(|info| info.connection_id == connection_id) {
            info.is_primary = true;
            info.last_used = Instant::now();
        } else {
            return Err(QuicError::Config(
                format!("Connection ID {} not found in active set", connection_id)
            ));
        }

        *self.primary_connection_id.write().await = Some(connection_id.clone());

        info!("Set primary connection ID to {}", connection_id);
        Ok(())
    }

    /// Get the current primary connection ID
    pub async fn get_primary_connection_id(&self) -> Option<ConnectionId> {
        self.primary_connection_id.read().await.clone()
    }

    /// Rotate connection IDs for privacy
    pub async fn rotate_connection_ids(&self) -> Result<Vec<Frame>> {
        if !self.config.enable_rotation {
            return Ok(Vec::new());
        }

        let mut frames = Vec::new();
        let now = Instant::now();

        // Check if rotation is needed
        let primary_id = self.primary_connection_id.read().await.clone();
        if let Some(primary_id) = primary_id {
            let active_ids = self.active_connection_ids.read().await;
            if let Some(primary_info) = active_ids.values().find(|info| info.connection_id == primary_id) {
                if now.duration_since(primary_info.created_at) < self.config.rotation_interval {
                    return Ok(Vec::new()); // Too early to rotate
                }
            }
        }

        drop(primary_id);

        // Generate new connection ID
        let (new_connection_id, sequence_number, stateless_reset_token) = 
            self.generate_connection_id().await?;

        // Create NEW_CONNECTION_ID frame
        frames.push(Frame::NewConnectionId {
            sequence_number,
            retire_prior_to: 0, // Don't force retirement of others
            connection_id: new_connection_id.clone(),
            stateless_reset_token: stateless_reset_token.unwrap_or([0u8; 16]),
        });

        // Update statistics
        let mut stats = self.stats.lock().await;
        stats.rotations_performed += 1;

        info!("Initiated connection ID rotation (new ID: {}, sequence: {})", 
              new_connection_id, sequence_number);

        Ok(frames)
    }

    /// Process NEW_CONNECTION_ID frame from peer
    pub async fn on_new_connection_id(
        &self,
        sequence_number: u64,
        retire_prior_to: u64,
        connection_id: ConnectionId,
        stateless_reset_token: [u8; 16],
    ) -> Result<Vec<Frame>> {
        let mut frames = Vec::new();
        let now = Instant::now();

        // Validate sequence number
        let active_ids = self.active_connection_ids.read().await;
        if active_ids.contains_key(&sequence_number) {
            warn!("Duplicate connection ID sequence number: {}", sequence_number);
            return Ok(frames);
        }

        // Check if we need to retire prior connection IDs
        let mut retire_sequences = Vec::new();
        for (&seq, _) in active_ids.iter() {
            if seq < retire_prior_to {
                retire_sequences.push(seq);
            }
        }
        drop(active_ids);

        // Retire old connection IDs
        for seq in retire_sequences {
            frames.extend(self.retire_connection_id(seq, RetirementReason::Rotation).await?);
        }

        // Store new connection ID
        let connection_id_info = ConnectionIdInfo {
            connection_id: connection_id.clone(),
            sequence_number,
            stateless_reset_token: Some(stateless_reset_token),
            created_at: now,
            last_used: now,
            is_primary: false,
            retire_prior_to: Some(retire_prior_to),
        };

        let mut active_ids = self.active_connection_ids.write().await;
        active_ids.insert(sequence_number, connection_id_info);

        debug!("Added new connection ID {} (sequence: {}, retire_prior_to: {})", 
               connection_id, sequence_number, retire_prior_to);

        Ok(frames)
    }

    /// Process RETIRE_CONNECTION_ID frame from peer
    pub async fn on_retire_connection_id(&self, sequence_number: u64) -> Result<()> {
        let mut active_ids = self.active_connection_ids.write().await;
        
        if let Some(info) = active_ids.remove(&sequence_number) {
            // Move to retiring collection
            let retiring_id = RetiringConnectionId {
                connection_id: info.connection_id.clone(),
                sequence_number,
                retirement_time: Instant::now(),
                reason: RetirementReason::Manual,
            };

            let mut retiring_ids = self.retiring_connection_ids.write().await;
            retiring_ids.insert(sequence_number, retiring_id);

            // Update statistics
            let mut stats = self.stats.lock().await;
            stats.connection_ids_retired += 1;

            info!("Retired connection ID {} (sequence: {})", 
                  info.connection_id, sequence_number);
        } else {
            warn!("Attempted to retire unknown connection ID sequence: {}", sequence_number);
        }

        Ok(())
    }

    /// Manually retire a connection ID
    pub async fn retire_connection_id(
        &self,
        sequence_number: u64,
        reason: RetirementReason,
    ) -> Result<Vec<Frame>> {
        let mut frames = Vec::new();

        let mut active_ids = self.active_connection_ids.write().await;
        if let Some(info) = active_ids.remove(&sequence_number) {
            // Don't retire the primary connection ID unless forced
            if info.is_primary && !matches!(reason, RetirementReason::Security) {
                active_ids.insert(sequence_number, info);
                return Ok(frames);
            }

            // Create RETIRE_CONNECTION_ID frame
            frames.push(Frame::RetireConnectionId {
                sequence_number,
            });

            // Move to retiring collection
            let retiring_id = RetiringConnectionId {
                connection_id: info.connection_id.clone(),
                sequence_number,
                retirement_time: Instant::now(),
                reason,
            };

            let mut retiring_ids = self.retiring_connection_ids.write().await;
            retiring_ids.insert(sequence_number, retiring_id);

            // Update statistics
            let mut stats = self.stats.lock().await;
            stats.connection_ids_retired += 1;

            info!("Retired connection ID {} (sequence: {}, reason: {:?})", 
                  info.connection_id, sequence_number, retiring_id.reason);
        }

        Ok(frames)
    }

    /// Check if connection ID is valid and active
    pub async fn is_valid_connection_id(&self, connection_id: &ConnectionId) -> bool {
        let active_ids = self.active_connection_ids.read().await;
        active_ids.values().any(|info| &info.connection_id == connection_id)
    }

    /// Get connection ID by sequence number
    pub async fn get_connection_id(&self, sequence_number: u64) -> Option<ConnectionId> {
        let active_ids = self.active_connection_ids.read().await;
        active_ids.get(&sequence_number).map(|info| info.connection_id.clone())
    }

    /// Update last used time for connection ID
    pub async fn mark_connection_id_used(&self, connection_id: &ConnectionId) {
        let mut active_ids = self.active_connection_ids.write().await;
        if let Some(info) = active_ids.values_mut().find(|info| &info.connection_id == connection_id) {
            info.last_used = Instant::now();
        }
    }

    /// Perform maintenance tasks
    pub async fn perform_maintenance(&self) -> Result<Vec<Frame>> {
        let mut frames = Vec::new();
        let now = Instant::now();

        // Clean up expired retiring connection IDs
        {
            let mut retiring_ids = self.retiring_connection_ids.write().await;
            retiring_ids.retain(|_, retiring_id| {
                now.duration_since(retiring_id.retirement_time) < Duration::from_secs(300)
            });
        }

        // Check for connection IDs that need rotation
        if self.config.enable_rotation {
            let rotation_frames = self.check_rotation_needed(now).await?;
            frames.extend(rotation_frames);
        }

        // Cleanup inactive connection IDs
        let cleanup_frames = self.cleanup_inactive_connection_ids(now).await?;
        frames.extend(cleanup_frames);

        Ok(frames)
    }

    /// Check if any connection IDs need rotation
    async fn check_rotation_needed(&self, now: Instant) -> Result<Vec<Frame>> {
        let mut frames = Vec::new();
        let active_ids = self.active_connection_ids.read().await;

        for info in active_ids.values() {
            if info.is_primary && 
               now.duration_since(info.created_at) > self.config.rotation_interval {
                drop(active_ids);
                frames.extend(self.rotate_connection_ids().await?);
                break;
            }
        }

        Ok(frames)
    }

    /// Cleanup inactive connection IDs
    async fn cleanup_inactive_connection_ids(&self, now: Instant) -> Result<Vec<Frame>> {
        let mut frames = Vec::new();
        let active_ids = self.active_connection_ids.read().await;
        
        // Find connection IDs that haven't been used recently
        let mut inactive_sequences = Vec::new();
        for (&sequence, info) in active_ids.iter() {
            if !info.is_primary && 
               now.duration_since(info.last_used) > self.config.min_lifetime * 2 &&
               active_ids.len() > 2 { // Keep at least 2 connection IDs
                inactive_sequences.push(sequence);
            }
        }
        drop(active_ids);

        // Retire inactive connection IDs
        for sequence in inactive_sequences {
            frames.extend(self.retire_connection_id(sequence, RetirementReason::Rotation).await?);
        }

        Ok(frames)
    }

    /// Generate stateless reset token
    fn generate_stateless_reset_token(&self, connection_id: &ConnectionId, secret_key: &[u8; 32]) -> [u8; 16] {
        let mut token = [0u8; 16];
        
        // Simple HMAC-like construction (in production, use proper HMAC)
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        std::hash::Hasher::write(&mut hasher, secret_key);
        std::hash::Hasher::write(&mut hasher, &connection_id.to_bytes());
        std::hash::Hasher::write(&mut hasher, b"stateless_reset");
        
        let hash = std::hash::Hasher::finish(&mut hasher);
        token[..8].copy_from_slice(&hash.to_be_bytes());
        
        // Add some randomness
        thread_rng().fill_bytes(&mut token[8..]);
        
        token
    }

    /// Derive entropy for connection ID generation
    fn derive_entropy(&self, secret_key: &[u8; 32], sequence_number: u64) -> [u8; 8] {
        let mut entropy = [0u8; 8];
        
        // Mix secret key with sequence number
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        std::hash::Hasher::write(&mut hasher, secret_key);
        std::hash::Hasher::write(&mut hasher, &sequence_number.to_be_bytes());
        
        let hash = std::hash::Hasher::finish(&mut hasher);
        entropy.copy_from_slice(&hash.to_be_bytes());
        
        entropy
    }

    /// Generate stateless reset packet
    pub async fn generate_stateless_reset(&self, received_connection_id: &ConnectionId) -> Option<Vec<u8>> {
        if !self.config.enable_privacy_protection {
            return None;
        }

        // Check if we have a stateless reset token for this connection ID
        let active_ids = self.active_connection_ids.read().await;
        let reset_token = active_ids.values()
            .find(|info| &info.connection_id == received_connection_id)
            .and_then(|info| info.stateless_reset_token)?;

        // Create stateless reset packet
        let mut packet = Vec::new();
        
        // Random bits (to look like a regular packet)
        let mut random_bits = vec![0u8; 32];
        thread_rng().fill(&mut random_bits[..]);
        packet.extend_from_slice(&random_bits);
        
        // Stateless reset token at the end
        packet.extend_from_slice(&reset_token);

        // Update statistics
        tokio::spawn({
            let stats = self.stats.clone();
            async move {
                let mut stats = stats.lock().await;
                stats.stateless_resets_sent += 1;
            }
        });

        Some(packet)
    }

    /// Get connection ID manager statistics
    pub async fn get_stats(&self) -> ConnectionIdStats {
        self.stats.lock().await.clone()
    }

    /// Get active connection IDs
    pub async fn get_active_connection_ids(&self) -> Vec<ConnectionId> {
        let active_ids = self.active_connection_ids.read().await;
        active_ids.values().map(|info| info.connection_id.clone()).collect()
    }

    /// Force immediate rotation (for security purposes)
    pub async fn force_rotation(&self) -> Result<Vec<Frame>> {
        info!("Forcing immediate connection ID rotation for security");
        
        let mut stats = self.stats.lock().await;
        stats.rotations_performed += 1;
        drop(stats);

        self.rotate_connection_ids().await
    }
}

/// Privacy analysis utilities
pub struct PrivacyAnalyzer {
    connection_id_manager: Arc<ConnectionIdManager>,
    tracking_detection: TrackingDetection,
}

#[derive(Debug)]
struct TrackingDetection {
    connection_patterns: HashMap<String, u32>,
    timing_patterns: VecDeque<Instant>,
    suspicious_activity_threshold: u32,
}

impl PrivacyAnalyzer {
    pub fn new(connection_id_manager: Arc<ConnectionIdManager>) -> Self {
        Self {
            connection_id_manager,
            tracking_detection: TrackingDetection {
                connection_patterns: HashMap::new(),
                timing_patterns: VecDeque::new(),
                suspicious_activity_threshold: 10,
            },
        }
    }

    /// Analyze potential privacy violations
    pub async fn analyze_privacy_risk(&mut self, peer_address: &str) -> PrivacyRiskLevel {
        // Check for correlation patterns
        let pattern_count = self.tracking_detection.connection_patterns
            .entry(peer_address.to_string())
            .or_insert(0);
        *pattern_count += 1;

        // Check timing patterns
        let now = Instant::now();
        self.tracking_detection.timing_patterns.push_back(now);
        
        // Keep only recent timings
        while let Some(&front_time) = self.tracking_detection.timing_patterns.front() {
            if now.duration_since(front_time) > Duration::from_secs(300) {
                self.tracking_detection.timing_patterns.pop_front();
            } else {
                break;
            }
        }

        // Determine risk level
        if *pattern_count > self.tracking_detection.suspicious_activity_threshold {
            PrivacyRiskLevel::High
        } else if self.tracking_detection.timing_patterns.len() > 50 {
            PrivacyRiskLevel::Medium
        } else {
            PrivacyRiskLevel::Low
        }
    }

    /// Recommend privacy protection actions
    pub async fn recommend_actions(&self, risk_level: PrivacyRiskLevel) -> Vec<PrivacyAction> {
        match risk_level {
            PrivacyRiskLevel::High => vec![
                PrivacyAction::ForceRotation,
                PrivacyAction::ChangeNetworkPath,
                PrivacyAction::EnableAdditionalObfuscation,
            ],
            PrivacyRiskLevel::Medium => vec![
                PrivacyAction::AccelerateRotation,
                PrivacyAction::IncreaseRandomness,
            ],
            PrivacyRiskLevel::Low => vec![
                PrivacyAction::MaintainCurrentPolicy,
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum PrivacyRiskLevel {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone)]
pub enum PrivacyAction {
    MaintainCurrentPolicy,
    AccelerateRotation,
    IncreaseRandomness,
    ForceRotation,
    ChangeNetworkPath,
    EnableAdditionalObfuscation,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_connection_id_generation() {
        let manager = ConnectionIdManager::new(ConnectionIdConfig::default());
        
        let (connection_id, sequence, reset_token) = manager.generate_connection_id().await.unwrap();
        
        assert_eq!(sequence, 0);
        assert!(reset_token.is_some());
        assert!(manager.is_valid_connection_id(&connection_id).await);
    }

    #[tokio::test]
    async fn test_connection_id_rotation() {
        let mut config = ConnectionIdConfig::default();
        config.rotation_interval = Duration::from_millis(1); // Very short for testing
        
        let manager = ConnectionIdManager::new(config);
        
        let (initial_id, sequence, _) = manager.generate_connection_id().await.unwrap();
        manager.set_primary_connection_id(initial_id.clone()).await.unwrap();
        
        tokio::time::sleep(Duration::from_millis(10)).await;
        
        let frames = manager.rotate_connection_ids().await.unwrap();
        assert!(!frames.is_empty());
        
        if let Frame::NewConnectionId { connection_id, .. } = &frames[0] {
            assert_ne!(*connection_id, initial_id);
        }
    }

    #[tokio::test]
    async fn test_connection_id_retirement() {
        let manager = ConnectionIdManager::new(ConnectionIdConfig::default());
        
        let (connection_id, sequence, _) = manager.generate_connection_id().await.unwrap();
        
        let frames = manager.retire_connection_id(sequence, RetirementReason::Manual).await.unwrap();
        assert!(!frames.is_empty());
        
        if let Frame::RetireConnectionId { sequence_number } = &frames[0] {
            assert_eq!(*sequence_number, sequence);
        }
        
        assert!(!manager.is_valid_connection_id(&connection_id).await);
    }

    #[tokio::test]
    async fn test_privacy_analyzer() {
        let manager = Arc::new(ConnectionIdManager::new(ConnectionIdConfig::default()));
        let mut analyzer = PrivacyAnalyzer::new(manager);
        
        let risk = analyzer.analyze_privacy_risk("192.168.1.1").await;
        assert_eq!(risk, PrivacyRiskLevel::Low);
        
        // Simulate multiple connections from same peer
        for _ in 0..15 {
            analyzer.analyze_privacy_risk("192.168.1.1").await;
        }
        
        let risk = analyzer.analyze_privacy_risk("192.168.1.1").await;
        assert_eq!(risk, PrivacyRiskLevel::High);
    }
}