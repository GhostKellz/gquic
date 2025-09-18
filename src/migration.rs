//! Connection Migration Implementation
//!
//! Provides seamless connection migration across network changes,
//! allowing connections to survive IP address changes and network switches.

use crate::{QuicError, QuicResult, Connection, ConnectionId};
use crate::quic::packet::{Packet, PacketType};
use crate::quic::frame::Frame;
use bytes::{Bytes, BytesMut, BufMut};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{SocketAddr, IpAddr};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio::time::{Duration, Instant, timeout};
use ring::rand::{self, SecureRandom};

/// Path for connection migration
#[derive(Debug, Clone, PartialEq)]
pub struct Path {
    /// Local address
    pub local: SocketAddr,
    /// Remote address
    pub remote: SocketAddr,
    /// Path ID
    pub path_id: u64,
    /// Path state
    pub state: PathState,
    /// Path validation data
    pub validation: Option<PathValidation>,
    /// Path statistics
    pub stats: PathStats,
}

/// Path state
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PathState {
    /// Path is being validated
    Validating,
    /// Path is active and validated
    Active,
    /// Path is a backup
    Backup,
    /// Path has failed
    Failed,
    /// Path is being abandoned
    Closing,
}

/// Path validation data
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PathValidation {
    /// Challenge data sent
    pub challenge: Vec<u8>,
    /// Response data expected
    pub expected_response: Vec<u8>,
    /// Validation start time
    pub started_at: Instant,
    /// Number of retries
    pub retries: u32,
}

/// Path statistics
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PathStats {
    /// Packets sent on this path
    pub packets_sent: u64,
    /// Packets received on this path
    pub packets_received: u64,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Current RTT
    pub rtt: Duration,
    /// Packet loss rate (0.0 - 1.0)
    pub loss_rate: f64,
    /// Last activity time
    pub last_activity: Option<Instant>,
}

/// Migration handler for managing connection migration
pub struct MigrationHandler {
    /// Active paths
    paths: Arc<RwLock<HashMap<u64, Path>>>,
    /// Primary path ID
    primary_path: Arc<RwLock<u64>>,
    /// Pending migrations
    pending_migrations: Arc<Mutex<VecDeque<MigrationRequest>>>,
    /// Migration configuration
    config: MigrationConfig,
    /// Random number generator
    rng: Arc<Mutex<rand::SystemRandom>>,
}

/// Migration configuration
#[derive(Debug, Clone)]
pub struct MigrationConfig {
    /// Enable connection migration
    pub enabled: bool,
    /// Enable proactive path validation
    pub proactive_validation: bool,
    /// Path validation timeout
    pub validation_timeout: Duration,
    /// Maximum validation retries
    pub max_validation_retries: u32,
    /// Maximum concurrent paths
    pub max_paths: usize,
    /// Path probe interval
    pub probe_interval: Duration,
    /// Enable NAT rebinding detection
    pub nat_rebinding_detection: bool,
    /// Migration threshold (RTT increase factor)
    pub migration_threshold: f64,
}

impl Default for MigrationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            proactive_validation: true,
            validation_timeout: Duration::from_secs(3),
            max_validation_retries: 3,
            max_paths: 4,
            probe_interval: Duration::from_secs(30),
            nat_rebinding_detection: true,
            migration_threshold: 1.5,
        }
    }
}

/// Migration request
#[derive(Debug, Clone)]
pub struct MigrationRequest {
    /// Source path
    pub from_path: u64,
    /// Target path
    pub to_path: u64,
    /// Reason for migration
    pub reason: MigrationReason,
    /// Request time
    pub requested_at: Instant,
}

/// Reason for migration
#[derive(Debug, Clone)]
pub enum MigrationReason {
    /// Network change detected
    NetworkChange,
    /// Path failure
    PathFailure,
    /// Better path available
    BetterPath,
    /// User requested
    UserRequested,
    /// NAT rebinding detected
    NatRebinding,
}

impl MigrationHandler {
    /// Create a new migration handler
    pub fn new(config: MigrationConfig) -> Self {
        Self {
            paths: Arc::new(RwLock::new(HashMap::new())),
            primary_path: Arc::new(RwLock::new(0)),
            pending_migrations: Arc::new(Mutex::new(VecDeque::new())),
            config,
            rng: Arc::new(Mutex::new(rand::SystemRandom::new())),
        }
    }

    /// Add a new path
    pub async fn add_path(&self, local: SocketAddr, remote: SocketAddr) -> QuicResult<u64> {
        let mut paths = self.paths.write().await;

        if paths.len() >= self.config.max_paths {
            return Err(QuicError::Protocol("Maximum paths reached".into()));
        }

        let path_id = self.generate_path_id().await?;

        let path = Path {
            local,
            remote,
            path_id,
            state: PathState::Validating,
            validation: None,
            stats: PathStats::default(),
        };

        paths.insert(path_id, path);

        // Start validation
        if self.config.enabled {
            self.validate_path(path_id).await?;
        }

        Ok(path_id)
    }

    /// Validate a path
    pub async fn validate_path(&self, path_id: u64) -> QuicResult<()> {
        let challenge = self.generate_challenge().await?;
        let expected_response = Self::compute_response(&challenge);

        let mut paths = self.paths.write().await;
        let path = paths.get_mut(&path_id)
            .ok_or_else(|| QuicError::Protocol("Path not found".into()))?;

        path.validation = Some(PathValidation {
            challenge: challenge.clone(),
            expected_response,
            started_at: Instant::now(),
            retries: 0,
        });

        path.state = PathState::Validating;

        Ok(())
    }

    /// Handle PATH_CHALLENGE frame
    pub async fn handle_path_challenge(
        &self,
        conn: &Connection,
        challenge: &[u8],
        from: SocketAddr,
    ) -> QuicResult<()> {
        // Send PATH_RESPONSE
        let response = Self::compute_response(challenge);
        conn.send_path_response(&response, from).await?;

        // Check if this is from a new path (NAT rebinding)
        if self.config.nat_rebinding_detection {
            let paths = self.paths.read().await;
            let known_path = paths.values().any(|p| p.remote == from);

            if !known_path {
                // Potential NAT rebinding, add new path
                drop(paths);
                let local = conn.local_addr()?;
                let new_path_id = self.add_path(local, from).await?;

                // Queue migration request
                let mut pending = self.pending_migrations.lock().await;
                pending.push_back(MigrationRequest {
                    from_path: *self.primary_path.read().await,
                    to_path: new_path_id,
                    reason: MigrationReason::NatRebinding,
                    requested_at: Instant::now(),
                });
            }
        }

        Ok(())
    }

    /// Handle PATH_RESPONSE frame
    pub async fn handle_path_response(
        &self,
        response: &[u8],
        from: SocketAddr,
    ) -> QuicResult<()> {
        let mut paths = self.paths.write().await;

        // Find path being validated
        for path in paths.values_mut() {
            if path.remote == from {
                if let Some(validation) = &path.validation {
                    if validation.expected_response == response {
                        // Path validated successfully
                        path.state = PathState::Active;
                        path.validation = None;
                        path.stats.last_activity = Some(Instant::now());
                        return Ok(());
                    }
                }
            }
        }

        Err(QuicError::Protocol("Invalid PATH_RESPONSE".into()))
    }

    /// Migrate to a new path
    pub async fn migrate_to_path(
        &self,
        conn: &mut Connection,
        new_path_id: u64,
    ) -> QuicResult<()> {
        if !self.config.enabled {
            return Err(QuicError::Protocol("Migration not enabled".into()));
        }

        let (new_path_local, new_path_remote) = {
            let paths = self.paths.read().await;
            let new_path = paths.get(&new_path_id)
                .ok_or_else(|| QuicError::Protocol("Path not found".into()))?;

            if new_path.state != PathState::Active {
                return Err(QuicError::Protocol("Path not active".into()));
            }

            (new_path.local, new_path.remote)
        };

        let old_path_id = *self.primary_path.read().await;

        // Update connection to use new path
        conn.set_path(new_path_local, new_path_remote)?;

        // Update primary path
        *self.primary_path.write().await = new_path_id;

        // Mark old path as backup
        let mut paths = self.paths.write().await;
        if let Some(old_path) = paths.get_mut(&old_path_id) {
            old_path.state = PathState::Backup;
        }

        Ok(())
    }

    /// Process pending migrations
    pub async fn process_migrations(&self, conn: &mut Connection) -> QuicResult<()> {
        let mut pending = self.pending_migrations.lock().await;

        while let Some(request) = pending.pop_front() {
            // Check if migration is still needed
            if self.should_migrate(&request).await? {
                self.migrate_to_path(conn, request.to_path).await?;
            }
        }

        Ok(())
    }

    /// Check if migration should proceed
    async fn should_migrate(&self, request: &MigrationRequest) -> QuicResult<bool> {
        let paths = self.paths.read().await;

        let from_path = paths.get(&request.from_path);
        let to_path = paths.get(&request.to_path);

        match (from_path, to_path) {
            (Some(from), Some(to)) => {
                // Check if target path is better
                match request.reason {
                    MigrationReason::PathFailure => Ok(from.state == PathState::Failed),
                    MigrationReason::BetterPath => {
                        Ok(to.stats.rtt < from.stats.rtt.mul_f64(self.config.migration_threshold))
                    }
                    _ => Ok(true),
                }
            }
            _ => Ok(false),
        }
    }

    /// Probe all backup paths
    pub async fn probe_paths(&self, conn: &Connection) -> QuicResult<()> {
        let paths = self.paths.read().await;

        for path in paths.values() {
            if path.state == PathState::Backup {
                // Send PATH_CHALLENGE on backup path
                let challenge = self.generate_challenge().await?;
                conn.send_path_challenge(&challenge, path.remote).await?;
            }
        }

        Ok(())
    }

    /// Get path statistics
    pub async fn get_path_stats(&self, path_id: u64) -> Option<PathStats> {
        let paths = self.paths.read().await;
        paths.get(&path_id).map(|p| p.stats.clone())
    }

    /// Update path statistics
    pub async fn update_path_stats(
        &self,
        path_id: u64,
        packets_sent: u64,
        bytes_sent: u64,
        rtt: Duration,
    ) {
        let mut paths = self.paths.write().await;
        if let Some(path) = paths.get_mut(&path_id) {
            path.stats.packets_sent += packets_sent;
            path.stats.bytes_sent += bytes_sent;
            path.stats.rtt = rtt;
            path.stats.last_activity = Some(Instant::now());
        }
    }

    /// Detect and handle path failure
    pub async fn detect_path_failure(&self, path_id: u64, loss_rate: f64) -> QuicResult<()> {
        let mut paths = self.paths.write().await;

        if let Some(path) = paths.get_mut(&path_id) {
            path.stats.loss_rate = loss_rate;

            // Mark as failed if loss rate too high
            if loss_rate > 0.5 {
                path.state = PathState::Failed;

                // Find alternative path
                let alternative = paths.values()
                    .filter(|p| p.path_id != path_id && p.state == PathState::Active)
                    .min_by_key(|p| p.stats.rtt.as_millis())
                    .map(|p| p.path_id);

                if let Some(alt_path_id) = alternative {
                    drop(paths);

                    // Queue migration
                    let mut pending = self.pending_migrations.lock().await;
                    pending.push_back(MigrationRequest {
                        from_path: path_id,
                        to_path: alt_path_id,
                        reason: MigrationReason::PathFailure,
                        requested_at: Instant::now(),
                    });
                }
            }
        }

        Ok(())
    }

    /// Generate path ID
    async fn generate_path_id(&self) -> QuicResult<u64> {
        let mut buf = [0u8; 8];
        let mut rng = self.rng.lock().await;
        rng.fill(&mut buf)
            .map_err(|_| QuicError::Crypto("Failed to generate path ID".into()))?;
        Ok(u64::from_be_bytes(buf))
    }

    /// Generate challenge data
    async fn generate_challenge(&self) -> QuicResult<Vec<u8>> {
        let mut challenge = vec![0u8; 8];
        let mut rng = self.rng.lock().await;
        rng.fill(&mut challenge)
            .map_err(|_| QuicError::Crypto("Failed to generate challenge".into()))?;
        Ok(challenge)
    }

    /// Compute response from challenge
    fn compute_response(challenge: &[u8]) -> Vec<u8> {
        // In real implementation, this might involve cryptographic operations
        // For now, just return the challenge as response
        challenge.to_vec()
    }
}

/// Migration-aware connection
pub struct MigratableConnection {
    /// Base connection
    conn: Connection,
    /// Migration handler
    migration: Arc<MigrationHandler>,
    /// Current path ID
    current_path: u64,
}

impl MigratableConnection {
    /// Create a new migratable connection
    pub fn new(conn: Connection, config: MigrationConfig) -> Self {
        Self {
            conn,
            migration: Arc::new(MigrationHandler::new(config)),
            current_path: 0,
        }
    }

    /// Add a migration path
    pub async fn add_migration_path(
        &mut self,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> QuicResult<()> {
        let path_id = self.migration.add_path(local, remote).await?;

        if self.current_path == 0 {
            self.current_path = path_id;
            *self.migration.primary_path.write().await = path_id;
        }

        Ok(())
    }

    /// Trigger migration to best available path
    pub async fn migrate_to_best_path(&mut self) -> QuicResult<()> {
        let paths = self.migration.paths.read().await;

        // Find best active path
        let best_path = paths.values()
            .filter(|p| p.state == PathState::Active)
            .min_by_key(|p| p.stats.rtt.as_millis())
            .map(|p| p.path_id);

        if let Some(path_id) = best_path {
            if path_id != self.current_path {
                drop(paths);
                self.migration.migrate_to_path(&mut self.conn, path_id).await?;
                self.current_path = path_id;
            }
        }

        Ok(())
    }

    /// Handle network change
    pub async fn handle_network_change(&mut self) -> QuicResult<()> {
        // Probe all paths
        self.migration.probe_paths(&self.conn).await?;

        // Process any pending migrations
        self.migration.process_migrations(&mut self.conn).await?;

        Ok(())
    }

    /// Get migration statistics
    pub async fn migration_stats(&self) -> MigrationStats {
        let paths = self.migration.paths.read().await;

        MigrationStats {
            total_paths: paths.len(),
            active_paths: paths.values().filter(|p| p.state == PathState::Active).count(),
            current_path: self.current_path,
            primary_path: *self.migration.primary_path.read().await,
        }
    }
}

/// Migration statistics
#[derive(Debug)]
pub struct MigrationStats {
    pub total_paths: usize,
    pub active_paths: usize,
    pub current_path: u64,
    pub primary_path: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_path_validation() {
        let handler = MigrationHandler::new(MigrationConfig::default());
        let local = "127.0.0.1:8080".parse().unwrap();
        let remote = "127.0.0.1:9090".parse().unwrap();

        let path_id = handler.add_path(local, remote).await.unwrap();
        assert!(path_id > 0);

        let paths = handler.paths.read().await;
        assert_eq!(paths.len(), 1);
        assert_eq!(paths.get(&path_id).unwrap().state, PathState::Validating);
    }

    #[tokio::test]
    async fn test_challenge_response() {
        let challenge = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let response = MigrationHandler::compute_response(&challenge);
        assert_eq!(challenge, response);
    }
}