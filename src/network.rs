//! Advanced Network Interface for GQUIC
//!
//! This module provides a unified network interface that combines UDP multiplexing,
//! multi-path capabilities, and advanced networking features for GQUIC connections.

use crate::quic::{
    connection::{Connection, ConnectionId},
    error::{QuicError, Result, ProtocolError},
};
use crate::udp_mux_advanced::{AdvancedUdpMux, AdvancedMuxConfig, MuxStats};
use crate::multipath::{MultiPathConnection, MultiPathConfig, PathId, MultiPathStats};
use bytes::Bytes;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Mutex, mpsc};
use tokio::task::JoinHandle;
use tokio::time::{timeout, sleep, interval};
use tracing::{debug, info, warn, error, trace};
use serde::{Serialize, Deserialize};

/// Unified network interface for GQUIC
#[derive(Debug)]
pub struct NetworkInterface {
    /// UDP multiplexer for socket management
    udp_mux: Arc<AdvancedUdpMux>,
    /// Multi-path connections
    multipath_connections: Arc<RwLock<HashMap<ConnectionId, Arc<MultiPathConnection>>>>,
    /// Network configuration
    config: NetworkConfig,
    /// Network event handler
    event_handler: Arc<RwLock<NetworkEventHandler>>,
    /// Background task handles
    task_handles: Vec<JoinHandle<()>>,
    /// Network statistics
    stats: Arc<RwLock<NetworkStats>>,
    /// Connection factory for creating new connections
    connection_factory: Arc<dyn ConnectionFactory>,
    /// Network interface state
    state: Arc<RwLock<NetworkState>>,
}

/// Configuration for the network interface
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Primary listening address
    pub primary_addr: SocketAddr,
    /// Additional listening addresses for multi-homing
    pub additional_addrs: Vec<SocketAddr>,
    /// UDP multiplexer configuration
    pub mux_config: AdvancedMuxConfig,
    /// Multi-path configuration
    pub multipath_config: MultiPathConfig,
    /// Enable automatic path discovery
    pub enable_path_discovery: bool,
    /// Path discovery interval
    pub path_discovery_interval: Duration,
    /// Enable bandwidth estimation
    pub enable_bandwidth_estimation: bool,
    /// Network interface monitoring interval
    pub monitoring_interval: Duration,
    /// Maximum concurrent connections
    pub max_connections: usize,
    /// Connection timeout
    pub connection_timeout: Duration,
    /// Enable connection migration
    pub enable_connection_migration: bool,
    /// Enable network interface failover
    pub enable_interface_failover: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            primary_addr: "0.0.0.0:443".parse().unwrap(),
            additional_addrs: Vec::new(),
            mux_config: AdvancedMuxConfig::default(),
            multipath_config: MultiPathConfig::default(),
            enable_path_discovery: true,
            path_discovery_interval: Duration::from_secs(30),
            enable_bandwidth_estimation: true,
            monitoring_interval: Duration::from_secs(10),
            max_connections: 10000,
            connection_timeout: Duration::from_secs(300),
            enable_connection_migration: true,
            enable_interface_failover: true,
        }
    }
}

/// Network interface state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkState {
    /// Interface is initializing
    Initializing,
    /// Interface is active and ready
    Active,
    /// Interface is in failover mode
    Failover,
    /// Interface is shutting down
    Shutdown,
}

/// Network events that can be handled
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    /// New connection established
    ConnectionEstablished {
        connection_id: ConnectionId,
        peer_addr: SocketAddr,
        paths: Vec<PathId>,
    },
    /// Connection closed
    ConnectionClosed {
        connection_id: ConnectionId,
        reason: String,
    },
    /// New path added to connection
    PathAdded {
        connection_id: ConnectionId,
        path_id: PathId,
    },
    /// Path removed from connection
    PathRemoved {
        connection_id: ConnectionId,
        path_id: PathId,
        reason: String,
    },
    /// Path migration occurred
    PathMigration {
        connection_id: ConnectionId,
        old_path: PathId,
        new_path: PathId,
    },
    /// Network interface failover
    InterfaceFailover {
        failed_addr: SocketAddr,
        backup_addr: SocketAddr,
    },
    /// Bandwidth estimation updated
    BandwidthEstimate {
        path_id: PathId,
        bandwidth_bps: u64,
        confidence: f64,
    },
}

/// Network event handler
#[derive(Debug)]
pub struct NetworkEventHandler {
    /// Event subscribers
    subscribers: Vec<Box<dyn NetworkEventSubscriber>>,
    /// Event queue for async processing
    event_queue: mpsc::UnboundedSender<NetworkEvent>,
}

/// Trait for handling network events
pub trait NetworkEventSubscriber: Send + Sync + std::fmt::Debug {
    /// Handle a network event
    fn handle_event(&self, event: &NetworkEvent);
}

/// Factory for creating connections
pub trait ConnectionFactory: Send + Sync + std::fmt::Debug {
    /// Create a new connection
    fn create_connection(
        &self,
        connection_id: ConnectionId,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
    ) -> Arc<Connection>;
}

/// Default connection factory
#[derive(Debug)]
pub struct DefaultConnectionFactory;

impl ConnectionFactory for DefaultConnectionFactory {
    fn create_connection(
        &self,
        connection_id: ConnectionId,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
    ) -> Arc<Connection> {
        // Create a basic UDP socket for the connection
        let socket = std::net::UdpSocket::bind(local_addr)
            .map(|s| Arc::new(tokio::net::UdpSocket::from_std(s).unwrap()))
            .unwrap_or_else(|_| {
                // Fallback to any available port
                Arc::new(tokio::net::UdpSocket::from_std(
                    std::net::UdpSocket::bind("0.0.0.0:0").unwrap()
                ).unwrap())
            });

        Arc::new(Connection::new(connection_id, peer_addr, socket, false))
    }
}

/// Network statistics
#[derive(Debug, Default, Clone)]
pub struct NetworkStats {
    /// Total connections created
    pub connections_created: u64,
    /// Active connections
    pub active_connections: usize,
    /// Total bytes sent across all connections
    pub total_bytes_sent: u64,
    /// Total bytes received across all connections
    pub total_bytes_received: u64,
    /// Total packets sent
    pub total_packets_sent: u64,
    /// Total packets received
    pub total_packets_received: u64,
    /// Connection migrations
    pub connection_migrations: u64,
    /// Path failures
    pub path_failures: u64,
    /// Interface failovers
    pub interface_failovers: u64,
    /// Average connection latency
    pub avg_connection_latency: Duration,
    /// Network utilization percentage
    pub network_utilization: f64,
    /// Multiplexer statistics
    pub mux_stats: Option<MuxStats>,
}

impl NetworkInterface {
    /// Create a new network interface
    pub async fn new(config: NetworkConfig) -> Result<Self> {
        info!("Creating network interface on {}", config.primary_addr);

        // Create UDP multiplexer
        let udp_mux = Arc::new(
            AdvancedUdpMux::new(
                config.primary_addr,
                config.additional_addrs.clone(),
                config.mux_config.clone(),
            ).await?
        );

        // Create event handler
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let event_handler = Arc::new(RwLock::new(NetworkEventHandler {
            subscribers: Vec::new(),
            event_queue: event_tx,
        }));

        // Start event processing task
        let event_handler_clone = Arc::clone(&event_handler);
        let event_task = tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                let handler = event_handler_clone.read().await;
                for subscriber in &handler.subscribers {
                    subscriber.handle_event(&event);
                }
            }
        });

        let mut interface = Self {
            udp_mux,
            multipath_connections: Arc::new(RwLock::new(HashMap::new())),
            config,
            event_handler,
            task_handles: vec![event_task],
            stats: Arc::new(RwLock::new(NetworkStats::default())),
            connection_factory: Arc::new(DefaultConnectionFactory),
            state: Arc::new(RwLock::new(NetworkState::Initializing)),
        };

        Ok(interface)
    }

    /// Start the network interface
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting network interface");

        // Start UDP multiplexer
        // Note: We can't call mutable methods on Arc<AdvancedUdpMux>
        // This would need to be refactored in a real implementation

        // Start background tasks
        self.start_monitoring_task().await;
        if self.config.enable_path_discovery {
            self.start_path_discovery_task().await;
        }

        // Update state
        {
            let mut state = self.state.write().await;
            *state = NetworkState::Active;
        }

        info!("Network interface started successfully");
        Ok(())
    }

    /// Start monitoring task
    async fn start_monitoring_task(&mut self) {
        let stats = Arc::clone(&self.stats);
        let multipath_connections = Arc::clone(&self.multipath_connections);
        let udp_mux = Arc::clone(&self.udp_mux);
        let interval_duration = self.config.monitoring_interval;

        let task = tokio::spawn(async move {
            let mut interval = interval(interval_duration);

            loop {
                interval.tick().await;

                // Update network statistics
                let mut stats_guard = stats.write().await;

                // Get connection count
                let connections = multipath_connections.read().await;
                stats_guard.active_connections = connections.len();

                // Get multiplexer stats
                stats_guard.mux_stats = Some(udp_mux.stats().await);

                // Calculate network utilization (simplified)
                stats_guard.network_utilization = (connections.len() as f64 / 10000.0 * 100.0).min(100.0);

                trace!("Network stats updated: {} active connections, {:.1}% utilization",
                       stats_guard.active_connections, stats_guard.network_utilization);
            }
        });

        self.task_handles.push(task);
    }

    /// Start path discovery task
    async fn start_path_discovery_task(&mut self) {
        let multipath_connections = Arc::clone(&self.multipath_connections);
        let interval_duration = self.config.path_discovery_interval;

        let task = tokio::spawn(async move {
            let mut interval = interval(interval_duration);

            loop {
                interval.tick().await;

                debug!("Running path discovery");

                // Get all connections
                let connections = multipath_connections.read().await;

                for (connection_id, multipath_conn) in connections.iter() {
                    // Check if we should discover new paths for this connection
                    let stats = multipath_conn.stats().await;

                    if stats.active_paths < 2 {
                        // Try to discover additional paths
                        // In a real implementation, this would:
                        // 1. Query available network interfaces
                        // 2. Test connectivity to peer via alternative paths
                        // 3. Add validated paths to the connection

                        debug!("Connection {} has only {} active paths, considering path discovery",
                               connection_id, stats.active_paths);
                    }
                }
            }
        });

        self.task_handles.push(task);
    }

    /// Create a new connection
    pub async fn create_connection(
        &self,
        connection_id: ConnectionId,
        peer_addr: SocketAddr,
        local_addr: Option<SocketAddr>,
    ) -> Result<Arc<MultiPathConnection>> {
        info!("Creating connection {} to {}", connection_id, peer_addr);

        // Determine local address
        let local_addr = local_addr.unwrap_or(self.config.primary_addr);

        // Create multi-path connection
        let multipath_conn = Arc::new(
            MultiPathConnection::new(
                connection_id.clone(),
                local_addr,
                peer_addr,
                self.config.multipath_config.clone(),
                Arc::clone(&self.udp_mux),
            ).await?
        );

        // Add to connections map
        {
            let mut connections = self.multipath_connections.write().await;
            connections.insert(connection_id.clone(), Arc::clone(&multipath_conn));
        }

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.connections_created += 1;
        }

        // Emit event
        self.emit_event(NetworkEvent::ConnectionEstablished {
            connection_id,
            peer_addr,
            paths: vec![], // Would populate with actual paths
        }).await;

        info!("Connection created successfully");
        Ok(multipath_conn)
    }

    /// Get an existing connection
    pub async fn get_connection(&self, connection_id: &ConnectionId) -> Option<Arc<MultiPathConnection>> {
        let connections = self.multipath_connections.read().await;
        connections.get(connection_id).cloned()
    }

    /// Remove a connection
    pub async fn remove_connection(&self, connection_id: &ConnectionId, reason: String) -> Result<()> {
        info!("Removing connection {}: {}", connection_id, reason);

        // Remove from connections map
        let removed = {
            let mut connections = self.multipath_connections.write().await;
            connections.remove(connection_id)
        };

        if removed.is_some() {
            // Remove from UDP multiplexer
            self.udp_mux.remove_connection(connection_id).await?;

            // Emit event
            self.emit_event(NetworkEvent::ConnectionClosed {
                connection_id: connection_id.clone(),
                reason,
            }).await;

            info!("Connection removed successfully");
        }

        Ok(())
    }

    /// Send data on a connection
    pub async fn send(&self, connection_id: &ConnectionId, data: Bytes) -> Result<()> {
        let connection = self.get_connection(connection_id).await
            .ok_or_else(|| QuicError::Protocol(ProtocolError::InvalidState(
                "Connection not found".to_string()
            )))?;

        connection.send_packet(data.clone()).await?;

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.total_packets_sent += 1;
            stats.total_bytes_sent += data.len() as u64;
        }

        Ok(())
    }

    /// Add a path to an existing connection
    pub async fn add_path(
        &self,
        connection_id: &ConnectionId,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Result<PathId> {
        let connection = self.get_connection(connection_id).await
            .ok_or_else(|| QuicError::Protocol(ProtocolError::InvalidState(
                "Connection not found".to_string()
            )))?;

        let path_id = connection.add_path(local_addr, remote_addr).await?;

        // Emit event
        self.emit_event(NetworkEvent::PathAdded {
            connection_id: connection_id.clone(),
            path_id: path_id.clone(),
        }).await;

        info!("Added path {} to connection {}", path_id, connection_id);
        Ok(path_id)
    }

    /// Remove a path from a connection
    pub async fn remove_path(
        &self,
        connection_id: &ConnectionId,
        path_id: &PathId,
        reason: String,
    ) -> Result<()> {
        let connection = self.get_connection(connection_id).await
            .ok_or_else(|| QuicError::Protocol(ProtocolError::InvalidState(
                "Connection not found".to_string()
            )))?;

        connection.remove_path(path_id).await?;

        // Emit event
        self.emit_event(NetworkEvent::PathRemoved {
            connection_id: connection_id.clone(),
            path_id: path_id.clone(),
            reason,
        }).await;

        info!("Removed path {} from connection {}", path_id, connection_id);
        Ok(())
    }

    /// Get network statistics
    pub async fn stats(&self) -> NetworkStats {
        self.stats.read().await.clone()
    }

    /// Subscribe to network events
    pub async fn subscribe_events(&self, subscriber: Box<dyn NetworkEventSubscriber>) {
        let mut handler = self.event_handler.write().await;
        handler.subscribers.push(subscriber);
    }

    /// Emit a network event
    async fn emit_event(&self, event: NetworkEvent) {
        let handler = self.event_handler.read().await;
        if let Err(_) = handler.event_queue.send(event) {
            warn!("Failed to send network event - channel closed");
        }
    }

    /// Get all active connections
    pub async fn get_all_connections(&self) -> Vec<(ConnectionId, Arc<MultiPathConnection>)> {
        let connections = self.multipath_connections.read().await;
        connections.iter().map(|(id, conn)| (id.clone(), Arc::clone(conn))).collect()
    }

    /// Shutdown the network interface
    pub async fn shutdown(&mut self) {
        info!("Shutting down network interface");

        // Update state
        {
            let mut state = self.state.write().await;
            *state = NetworkState::Shutdown;
        }

        // Close all connections
        let connections: Vec<_> = {
            let connections = self.multipath_connections.read().await;
            connections.keys().cloned().collect()
        };

        for connection_id in connections {
            if let Err(e) = self.remove_connection(&connection_id, "Interface shutdown".to_string()).await {
                warn!("Error closing connection {} during shutdown: {}", connection_id, e);
            }
        }

        // Cancel all background tasks
        for handle in self.task_handles.drain(..) {
            handle.abort();
        }

        info!("Network interface shutdown complete");
    }

    /// Get current network state
    pub async fn state(&self) -> NetworkState {
        self.state.read().await.clone()
    }
}

impl Drop for NetworkInterface {
    fn drop(&mut self) {
        // Abort any remaining tasks
        for handle in &self.task_handles {
            handle.abort();
        }
    }
}

/// Default network event subscriber that logs events
#[derive(Debug)]
pub struct LoggingEventSubscriber;

impl NetworkEventSubscriber for LoggingEventSubscriber {
    fn handle_event(&self, event: &NetworkEvent) {
        match event {
            NetworkEvent::ConnectionEstablished { connection_id, peer_addr, paths } => {
                info!("Connection established: {} -> {} ({} paths)",
                      connection_id, peer_addr, paths.len());
            },
            NetworkEvent::ConnectionClosed { connection_id, reason } => {
                info!("Connection closed: {} ({})", connection_id, reason);
            },
            NetworkEvent::PathAdded { connection_id, path_id } => {
                debug!("Path added: {} -> {}", connection_id, path_id);
            },
            NetworkEvent::PathRemoved { connection_id, path_id, reason } => {
                debug!("Path removed: {} -> {} ({})", connection_id, path_id, reason);
            },
            NetworkEvent::PathMigration { connection_id, old_path, new_path } => {
                info!("Path migration: {} -> {} to {}", connection_id, old_path, new_path);
            },
            NetworkEvent::InterfaceFailover { failed_addr, backup_addr } => {
                warn!("Interface failover: {} -> {}", failed_addr, backup_addr);
            },
            NetworkEvent::BandwidthEstimate { path_id, bandwidth_bps, confidence } => {
                debug!("Bandwidth estimate: {} -> {} bps (confidence: {:.2})",
                       path_id, bandwidth_bps, confidence);
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_network_interface_creation() {
        let config = NetworkConfig {
            primary_addr: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        };

        let interface = NetworkInterface::new(config).await;
        assert!(interface.is_ok());
    }

    #[tokio::test]
    async fn test_connection_management() {
        let config = NetworkConfig {
            primary_addr: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        };

        let interface = NetworkInterface::new(config).await.unwrap();

        let connection_id = ConnectionId::from_bytes(&[1, 2, 3, 4]);
        let peer_addr = "127.0.0.1:8080".parse().unwrap();

        // Create connection
        let result = interface.create_connection(connection_id.clone(), peer_addr, None).await;
        assert!(result.is_ok());

        // Get connection
        let conn = interface.get_connection(&connection_id).await;
        assert!(conn.is_some());

        // Remove connection
        let result = interface.remove_connection(&connection_id, "Test completed".to_string()).await;
        assert!(result.is_ok());

        // Verify connection is removed
        let conn = interface.get_connection(&connection_id).await;
        assert!(conn.is_none());
    }

    #[tokio::test]
    async fn test_event_subscription() {
        let config = NetworkConfig {
            primary_addr: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        };

        let interface = NetworkInterface::new(config).await.unwrap();

        // Subscribe to events
        interface.subscribe_events(Box::new(LoggingEventSubscriber)).await;

        // Events should be handled by the subscriber
        // (This is a basic test - real implementation would verify event handling)
    }
}