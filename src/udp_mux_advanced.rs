//! Advanced UDP Multiplexing for GQUIC
//!
//! This module provides advanced UDP multiplexing capabilities for GQUIC,
//! enabling efficient handling of multiple QUIC connections over shared sockets,
//! connection migration, and advanced networking features.

use crate::quic::{
    connection::{Connection, ConnectionId},
    error::{QuicError, Result},
    packet::{Packet, PacketHeader},
};
use bytes::{Bytes, BytesMut};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, Mutex};
use tokio::task::JoinHandle;
use tokio::time::{timeout, sleep};
use tracing::{debug, info, warn, error, trace};

/// Advanced UDP multiplexer with enhanced networking capabilities
#[derive(Debug)]
pub struct AdvancedUdpMux {
    /// Primary UDP socket for standard connections
    primary_socket: Arc<UdpSocket>,
    /// Secondary sockets for multi-path and redundancy
    secondary_sockets: Vec<Arc<UdpSocket>>,
    /// Connection mapping by destination connection ID
    connections: Arc<RwLock<HashMap<ConnectionId, Arc<Connection>>>>,
    /// Connection mapping by source address (for migration support)
    addr_connections: Arc<RwLock<HashMap<SocketAddr, Vec<ConnectionId>>>>,
    /// Configuration for the multiplexer
    config: AdvancedMuxConfig,
    /// Statistics and metrics
    stats: Arc<RwLock<MuxStats>>,
    /// Background task handles
    task_handles: Vec<JoinHandle<()>>,
    /// Connection migration tracker
    migration_tracker: Arc<RwLock<HashMap<ConnectionId, MigrationState>>>,
    /// Load balancer for multiple sockets
    load_balancer: Arc<Mutex<LoadBalancer>>,
}

/// Configuration for advanced UDP multiplexing
#[derive(Debug, Clone)]
pub struct AdvancedMuxConfig {
    /// Maximum number of connections per socket
    pub max_connections_per_socket: usize,
    /// Enable connection migration support
    pub enable_migration: bool,
    /// Enable multi-path support
    pub enable_multipath: bool,
    /// Enable automatic load balancing
    pub enable_load_balancing: bool,
    /// Socket buffer sizes
    pub socket_recv_buffer_size: usize,
    pub socket_send_buffer_size: usize,
    /// Connection migration timeout
    pub migration_timeout: Duration,
    /// Packet processing batch size
    pub batch_size: usize,
    /// Enable packet coalescing
    pub enable_coalescing: bool,
    /// Maximum coalesced packet size
    pub max_coalesced_size: usize,
    /// Enable GSO (Generic Segmentation Offload)
    pub enable_gso: bool,
    /// Enable GRO (Generic Receive Offload)
    pub enable_gro: bool,
}

impl Default for AdvancedMuxConfig {
    fn default() -> Self {
        Self {
            max_connections_per_socket: 10000,
            enable_migration: true,
            enable_multipath: true,
            enable_load_balancing: true,
            socket_recv_buffer_size: 2 * 1024 * 1024, // 2MB
            socket_send_buffer_size: 2 * 1024 * 1024, // 2MB
            migration_timeout: Duration::from_secs(30),
            batch_size: 64,
            enable_coalescing: true,
            max_coalesced_size: 1500,
            enable_gso: true,
            enable_gro: true,
        }
    }
}

/// Statistics for UDP multiplexer
#[derive(Debug, Default)]
pub struct MuxStats {
    /// Total packets received
    pub packets_received: u64,
    /// Total packets sent
    pub packets_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Active connections count
    pub active_connections: usize,
    /// Failed connections count
    pub failed_connections: u64,
    /// Connection migrations count
    pub migrations: u64,
    /// Load balancing decisions
    pub load_balance_decisions: u64,
    /// Packet processing latency (microseconds)
    pub avg_processing_latency_us: u64,
    /// Socket utilization percentage
    pub socket_utilization: f64,
}

/// Connection migration state
#[derive(Debug, Clone)]
struct MigrationState {
    /// Original address
    original_addr: SocketAddr,
    /// New address (if migrating)
    new_addr: Option<SocketAddr>,
    /// Migration start time
    migration_start: Instant,
    /// Migration attempt count
    attempt_count: u32,
}

/// Load balancer for socket selection
#[derive(Debug)]
struct LoadBalancer {
    /// Round-robin counter
    round_robin_counter: usize,
    /// Socket load metrics
    socket_loads: Vec<SocketLoad>,
    /// Load balancing strategy
    strategy: LoadBalanceStrategy,
}

/// Socket load information
#[derive(Debug, Default)]
struct SocketLoad {
    /// Active connections on this socket
    active_connections: usize,
    /// Recent throughput (bytes per second)
    recent_throughput: u64,
    /// Error rate (errors per minute)
    error_rate: f64,
    /// Last update time
    last_update: Instant,
}

/// Load balancing strategies
#[derive(Debug, Clone)]
pub enum LoadBalanceStrategy {
    /// Round-robin distribution
    RoundRobin,
    /// Least connections
    LeastConnections,
    /// Least loaded (by throughput)
    LeastLoaded,
    /// Weighted distribution
    Weighted(Vec<f64>),
}

impl AdvancedUdpMux {
    /// Create a new advanced UDP multiplexer
    pub async fn new(
        primary_addr: SocketAddr,
        secondary_addrs: Vec<SocketAddr>,
        config: AdvancedMuxConfig,
    ) -> Result<Self> {
        info!("Creating advanced UDP multiplexer on {}", primary_addr);

        // Create primary socket
        let primary_socket = Arc::new(UdpSocket::bind(primary_addr).await
            .map_err(|e| QuicError::Io(e.to_string()))?);

        // Configure socket options
        Self::configure_socket(&primary_socket, &config).await?;

        // Create secondary sockets
        let mut secondary_sockets = Vec::new();
        for addr in secondary_addrs {
            let socket = Arc::new(UdpSocket::bind(addr).await
                .map_err(|e| QuicError::Io(e.to_string()))?);
            Self::configure_socket(&socket, &config).await?;
            secondary_sockets.push(socket);
        }

        // Initialize load balancer
        let socket_count = 1 + secondary_sockets.len();
        let load_balancer = Arc::new(Mutex::new(LoadBalancer {
            round_robin_counter: 0,
            socket_loads: vec![SocketLoad::default(); socket_count],
            strategy: LoadBalanceStrategy::LeastConnections,
        }));

        let mux = Self {
            primary_socket,
            secondary_sockets,
            connections: Arc::new(RwLock::new(HashMap::new())),
            addr_connections: Arc::new(RwLock::new(HashMap::new())),
            config,
            stats: Arc::new(RwLock::new(MuxStats::default())),
            task_handles: Vec::new(),
            migration_tracker: Arc::new(RwLock::new(HashMap::new())),
            load_balancer,
        };

        Ok(mux)
    }

    /// Configure socket with advanced options
    async fn configure_socket(socket: &UdpSocket, config: &AdvancedMuxConfig) -> Result<()> {
        // Set socket buffer sizes
        socket.set_recv_buffer_size(config.socket_recv_buffer_size)
            .map_err(|e| QuicError::Io(e.to_string()))?;
        socket.set_send_buffer_size(config.socket_send_buffer_size)
            .map_err(|e| QuicError::Io(e.to_string()))?;

        debug!("Configured socket with recv_buf={}, send_buf={}",
               config.socket_recv_buffer_size, config.socket_send_buffer_size);

        Ok(())
    }

    /// Start the multiplexer with background tasks
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting advanced UDP multiplexer");

        // Start packet processing tasks for each socket
        let primary_handle = self.start_socket_task(Arc::clone(&self.primary_socket), 0).await;
        self.task_handles.push(primary_handle);

        for (idx, socket) in self.secondary_sockets.iter().enumerate() {
            let handle = self.start_socket_task(Arc::clone(socket), idx + 1).await;
            self.task_handles.push(handle);
        }

        // Start background maintenance tasks
        if self.config.enable_migration {
            let migration_handle = self.start_migration_task().await;
            self.task_handles.push(migration_handle);
        }

        let stats_handle = self.start_stats_task().await;
        self.task_handles.push(stats_handle);

        Ok(())
    }

    /// Start packet processing task for a socket
    async fn start_socket_task(&self, socket: Arc<UdpSocket>, socket_index: usize) -> JoinHandle<()> {
        let connections = Arc::clone(&self.connections);
        let addr_connections = Arc::clone(&self.addr_connections);
        let stats = Arc::clone(&self.stats);
        let config = self.config.clone();
        let migration_tracker = Arc::clone(&self.migration_tracker);
        let load_balancer = Arc::clone(&self.load_balancer);

        tokio::spawn(async move {
            let mut buffer = BytesMut::with_capacity(65536);
            let mut batch_buffer = Vec::with_capacity(config.batch_size);

            loop {
                buffer.clear();
                buffer.resize(65536, 0);

                match socket.recv_from(&mut buffer).await {
                    Ok((len, src_addr)) => {
                        buffer.truncate(len);

                        // Update socket load metrics
                        {
                            let mut lb = load_balancer.lock().await;
                            if socket_index < lb.socket_loads.len() {
                                lb.socket_loads[socket_index].recent_throughput += len as u64;
                                lb.socket_loads[socket_index].last_update = Instant::now();
                            }
                        }

                        // Process packet
                        if let Err(e) = Self::process_incoming_packet(
                            buffer.freeze(),
                            src_addr,
                            &connections,
                            &addr_connections,
                            &stats,
                            &config,
                            &migration_tracker,
                        ).await {
                            trace!("Failed to process packet from {}: {}", src_addr, e);
                        }
                    },
                    Err(e) => {
                        error!("Socket recv error: {}", e);
                        sleep(Duration::from_millis(10)).await;
                    }
                }
            }
        })
    }

    /// Process incoming packet with advanced routing
    async fn process_incoming_packet(
        packet_data: Bytes,
        src_addr: SocketAddr,
        connections: &Arc<RwLock<HashMap<ConnectionId, Arc<Connection>>>>,
        addr_connections: &Arc<RwLock<HashMap<SocketAddr, Vec<ConnectionId>>>>,
        stats: &Arc<RwLock<MuxStats>>,
        config: &AdvancedMuxConfig,
        migration_tracker: &Arc<RwLock<HashMap<ConnectionId, MigrationState>>>,
    ) -> Result<()> {
        let start_time = Instant::now();

        // Parse packet header to extract connection ID
        let connection_id = match Self::extract_connection_id(&packet_data) {
            Ok(cid) => cid,
            Err(e) => {
                trace!("Failed to extract connection ID: {}", e);
                return Err(e);
            }
        };

        // Find connection by connection ID
        let connection = {
            let conns = connections.read().await;
            conns.get(&connection_id).cloned()
        };

        if let Some(conn) = connection {
            // Handle potential connection migration
            if config.enable_migration {
                Self::handle_connection_migration(
                    &connection_id,
                    src_addr,
                    &conn,
                    migration_tracker,
                ).await?;
            }

            // Process packet with connection
            // conn.process_packet(packet_data, src_addr).await?;

            // Update statistics
            {
                let mut stats_guard = stats.write().await;
                stats_guard.packets_received += 1;
                stats_guard.bytes_received += packet_data.len() as u64;
                stats_guard.avg_processing_latency_us =
                    (stats_guard.avg_processing_latency_us + start_time.elapsed().as_micros() as u64) / 2;
            }
        } else {
            // Handle new connection or stateless packets
            Self::handle_stateless_packet(
                packet_data,
                src_addr,
                &connection_id,
                connections,
                addr_connections,
                stats,
            ).await?;
        }

        Ok(())
    }

    /// Extract connection ID from packet
    fn extract_connection_id(packet_data: &[u8]) -> Result<ConnectionId> {
        if packet_data.is_empty() {
            return Err(QuicError::Protocol(crate::quic::error::ProtocolError::InvalidPacket("Empty packet".to_string())));
        }

        let first_byte = packet_data[0];

        if (first_byte & 0x80) != 0 {
            // Long header packet
            if packet_data.len() < 6 {
                return Err(QuicError::Protocol(crate::quic::error::ProtocolError::InvalidPacket("Packet too short for long header".to_string())));
            }

            let dcid_len = packet_data[5] as usize;
            if packet_data.len() < 6 + dcid_len {
                return Err(QuicError::Protocol(crate::quic::error::ProtocolError::InvalidPacket("Packet too short for DCID".to_string())));
            }

            let dcid_bytes = &packet_data[6..6 + dcid_len];
            Ok(ConnectionId::new(dcid_bytes.to_vec()))
        } else {
            // Short header packet - use a fixed-length connection ID
            // In practice, the length would be negotiated during handshake
            let dcid_len = 8; // Assuming 8-byte connection IDs
            if packet_data.len() < 1 + dcid_len {
                return Err(QuicError::Protocol(crate::quic::error::ProtocolError::InvalidPacket("Packet too short for short header DCID".to_string())));
            }

            let dcid_bytes = &packet_data[1..1 + dcid_len];
            Ok(ConnectionId::new(dcid_bytes.to_vec()))
        }
    }

    /// Handle connection migration
    async fn handle_connection_migration(
        connection_id: &ConnectionId,
        src_addr: SocketAddr,
        connection: &Arc<Connection>,
        migration_tracker: &Arc<RwLock<HashMap<ConnectionId, MigrationState>>>,
    ) -> Result<()> {
        let mut tracker = migration_tracker.write().await;

        // Check if this is a new address for the connection
        let current_addr = connection.peer_addr().await;

        if current_addr != src_addr {
            if let Some(migration_state) = tracker.get_mut(connection_id) {
                // Update existing migration
                migration_state.new_addr = Some(src_addr);
                migration_state.attempt_count += 1;

                debug!("Connection migration update: {} -> {}", current_addr, src_addr);
            } else {
                // Start new migration
                let migration_state = MigrationState {
                    original_addr: current_addr,
                    new_addr: Some(src_addr),
                    migration_start: Instant::now(),
                    attempt_count: 1,
                };

                tracker.insert(connection_id.clone(), migration_state);
                info!("Started connection migration: {} -> {}", current_addr, src_addr);
            }

            // Update connection's peer address
            // connection.update_peer_addr(src_addr).await?;
        }

        Ok(())
    }

    /// Handle stateless packets (version negotiation, retry, etc.)
    async fn handle_stateless_packet(
        packet_data: Bytes,
        src_addr: SocketAddr,
        connection_id: &ConnectionId,
        connections: &Arc<RwLock<HashMap<ConnectionId, Arc<Connection>>>>,
        addr_connections: &Arc<RwLock<HashMap<SocketAddr, Vec<ConnectionId>>>>,
        stats: &Arc<RwLock<MuxStats>>,
    ) -> Result<()> {
        debug!("Handling stateless packet from {}", src_addr);

        // This would typically handle:
        // - Version negotiation packets
        // - Retry packets
        // - Initial packets for new connections
        // - Stateless reset packets

        // For now, we'll just update statistics
        {
            let mut stats_guard = stats.write().await;
            stats_guard.packets_received += 1;
            stats_guard.bytes_received += packet_data.len() as u64;
        }

        Ok(())
    }

    /// Start connection migration cleanup task
    async fn start_migration_task(&self) -> JoinHandle<()> {
        let migration_tracker = Arc::clone(&self.migration_tracker);
        let timeout = self.config.migration_timeout;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));

            loop {
                interval.tick().await;

                let now = Instant::now();
                let mut tracker = migration_tracker.write().await;

                // Clean up expired migrations
                tracker.retain(|conn_id, migration| {
                    if now.duration_since(migration.migration_start) > timeout {
                        debug!("Migration timeout for connection {}", conn_id);
                        false
                    } else {
                        true
                    }
                });
            }
        })
    }

    /// Start statistics collection task
    async fn start_stats_task(&self) -> JoinHandle<()> {
        let stats = Arc::clone(&self.stats);
        let connections = Arc::clone(&self.connections);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));

            loop {
                interval.tick().await;

                // Update connection count
                let conn_count = connections.read().await.len();
                let mut stats_guard = stats.write().await;
                stats_guard.active_connections = conn_count;

                // Calculate socket utilization
                // This is a simplified calculation
                stats_guard.socket_utilization =
                    (conn_count as f64 / 10000.0 * 100.0).min(100.0);
            }
        })
    }

    /// Add a new connection to the multiplexer
    pub async fn add_connection(&self, connection: Arc<Connection>) -> Result<()> {
        let connection_id = connection.connection_id().await;
        let peer_addr = connection.peer_addr().await;

        debug!("Adding connection {} for peer {}", connection_id, peer_addr);

        // Add to connections map
        {
            let mut conns = self.connections.write().await;
            conns.insert(connection_id.clone(), connection);
        }

        // Add to address mapping
        {
            let mut addr_conns = self.addr_connections.write().await;
            addr_conns.entry(peer_addr).or_insert_with(Vec::new).push(connection_id);
        }

        Ok(())
    }

    /// Remove a connection from the multiplexer
    pub async fn remove_connection(&self, connection_id: &ConnectionId) -> Result<()> {
        debug!("Removing connection {}", connection_id);

        // Remove from connections map
        let removed_conn = {
            let mut conns = self.connections.write().await;
            conns.remove(connection_id)
        };

        if let Some(conn) = removed_conn {
            let peer_addr = conn.peer_addr().await;

            // Remove from address mapping
            {
                let mut addr_conns = self.addr_connections.write().await;
                if let Some(conn_ids) = addr_conns.get_mut(&peer_addr) {
                    conn_ids.retain(|id| id != connection_id);
                    if conn_ids.is_empty() {
                        addr_conns.remove(&peer_addr);
                    }
                }
            }

            // Remove from migration tracker
            {
                let mut tracker = self.migration_tracker.write().await;
                tracker.remove(connection_id);
            }
        }

        Ok(())
    }

    /// Get multiplexer statistics
    pub async fn stats(&self) -> MuxStats {
        self.stats.read().await.clone()
    }

    /// Get the best socket for sending to a specific address
    pub async fn select_socket(&self, dest_addr: SocketAddr) -> Arc<UdpSocket> {
        let mut lb = self.load_balancer.lock().await;

        match lb.strategy {
            LoadBalanceStrategy::RoundRobin => {
                let socket_index = lb.round_robin_counter % (1 + self.secondary_sockets.len());
                lb.round_robin_counter += 1;

                if socket_index == 0 {
                    Arc::clone(&self.primary_socket)
                } else {
                    Arc::clone(&self.secondary_sockets[socket_index - 1])
                }
            },
            LoadBalanceStrategy::LeastConnections => {
                // Find socket with least connections
                let mut min_connections = usize::MAX;
                let mut best_socket_index = 0;

                for (idx, load) in lb.socket_loads.iter().enumerate() {
                    if load.active_connections < min_connections {
                        min_connections = load.active_connections;
                        best_socket_index = idx;
                    }
                }

                if best_socket_index == 0 {
                    Arc::clone(&self.primary_socket)
                } else {
                    Arc::clone(&self.secondary_sockets[best_socket_index - 1])
                }
            },
            LoadBalanceStrategy::LeastLoaded => {
                // Find socket with least throughput
                let mut min_throughput = u64::MAX;
                let mut best_socket_index = 0;

                for (idx, load) in lb.socket_loads.iter().enumerate() {
                    if load.recent_throughput < min_throughput {
                        min_throughput = load.recent_throughput;
                        best_socket_index = idx;
                    }
                }

                if best_socket_index == 0 {
                    Arc::clone(&self.primary_socket)
                } else {
                    Arc::clone(&self.secondary_sockets[best_socket_index - 1])
                }
            },
            LoadBalanceStrategy::Weighted(_weights) => {
                // Simplified weighted selection - use round-robin for now
                let socket_index = lb.round_robin_counter % (1 + self.secondary_sockets.len());
                lb.round_robin_counter += 1;

                if socket_index == 0 {
                    Arc::clone(&self.primary_socket)
                } else {
                    Arc::clone(&self.secondary_sockets[socket_index - 1])
                }
            },
        }
    }

    /// Send packet with optimal socket selection
    pub async fn send_packet(&self, packet_data: Bytes, dest_addr: SocketAddr) -> Result<usize> {
        let socket = self.select_socket(dest_addr).await;
        let bytes_sent = socket.send_to(&packet_data, dest_addr).await
            .map_err(|e| QuicError::Io(e.to_string()))?;

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.packets_sent += 1;
            stats.bytes_sent += bytes_sent as u64;
        }

        debug!("Sent {} bytes to {}", bytes_sent, dest_addr);
        Ok(bytes_sent)
    }

    /// Shutdown the multiplexer
    pub async fn shutdown(&mut self) {
        info!("Shutting down advanced UDP multiplexer");

        // Cancel all background tasks
        for handle in self.task_handles.drain(..) {
            handle.abort();
        }

        // Close all connections
        let connections: Vec<_> = {
            let conns = self.connections.read().await;
            conns.values().cloned().collect()
        };

        for conn in connections {
            if let Err(e) = conn.close(0, "Multiplexer shutdown").await {
                warn!("Error closing connection during shutdown: {}", e);
            }
        }

        info!("Advanced UDP multiplexer shutdown complete");
    }
}

impl Drop for AdvancedUdpMux {
    fn drop(&mut self) {
        // Abort any remaining tasks
        for handle in &self.task_handles {
            handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_advanced_mux_creation() {
        let config = AdvancedMuxConfig::default();
        let primary_addr = "127.0.0.1:0".parse().unwrap();
        let secondary_addrs = vec!["127.0.0.1:0".parse().unwrap()];

        let mux = AdvancedUdpMux::new(primary_addr, secondary_addrs, config).await;
        assert!(mux.is_ok());
    }

    #[test]
    fn test_connection_id_extraction() {
        // Test long header packet
        let long_header = vec![
            0x80, // Long header
            0x00, 0x00, 0x00, 0x01, // Version
            0x08, // DCID length
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DCID
        ];

        let cid = AdvancedUdpMux::extract_connection_id(&long_header).unwrap();
        assert_eq!(cid.as_bytes(), &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);

        // Test short header packet
        let short_header = vec![
            0x40, // Short header
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DCID (8 bytes)
        ];

        let cid = AdvancedUdpMux::extract_connection_id(&short_header).unwrap();
        assert_eq!(cid.as_bytes(), &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    }

    #[tokio::test]
    async fn test_load_balancer() {
        let config = AdvancedMuxConfig::default();
        let primary_addr = "127.0.0.1:0".parse().unwrap();
        let secondary_addrs = vec!["127.0.0.1:0".parse().unwrap()];

        let mux = AdvancedUdpMux::new(primary_addr, secondary_addrs, config).await.unwrap();

        // Test socket selection
        let dest_addr = "127.0.0.1:8080".parse().unwrap();
        let socket1 = mux.select_socket(dest_addr).await;
        let socket2 = mux.select_socket(dest_addr).await;

        // With round-robin, we should get different sockets
        assert!(!Arc::ptr_eq(&socket1, &socket2));
    }
}