//! GQUIC Mesh Networking - Premier QUIC library for mesh VPNs
//!
//! This module provides comprehensive mesh networking capabilities for:
//! - GhostWire (Tailscale/Headscale clone)
//! - HTTP/3 proxy infrastructure
//! - General-purpose QUIC applications
//! - Direct Quinn replacement

use crate::quic::error::{QuicError, Result};
use crate::quic::stream::StreamId;
use crate::quic::connection::{Connection, ConnectionId};
use bytes::Bytes;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock, Mutex};
use tokio::net::UdpSocket;
use tracing::{debug, info, warn, error};
use serde::{Serialize, Deserialize};

/// Peer identifier in the mesh network
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerId(pub String);

impl PeerId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn generate() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Transport backend options
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportBackend {
    /// Pure GQUIC implementation (default)
    Native,
    /// Fallback to Quinn for compatibility
    Quinn,
    /// Hybrid mode with WireGuard userspace
    WireGuard,
    /// DERP relay fallback
    Relay,
}

/// Connection strategy for mesh networking
#[derive(Debug, Clone)]
pub struct ConnectionStrategy {
    pub primary: TransportBackend,
    pub fallback: Option<TransportBackend>,
    pub max_connections_per_peer: usize,
    pub connection_timeout: Duration,
    pub retry_strategy: RetryStrategy,
}

impl Default for ConnectionStrategy {
    fn default() -> Self {
        Self {
            primary: TransportBackend::Native,
            fallback: Some(TransportBackend::Quinn),
            max_connections_per_peer: 3,
            connection_timeout: Duration::from_secs(10),
            retry_strategy: RetryStrategy::ExponentialBackoff {
                initial_delay: Duration::from_millis(100),
                max_delay: Duration::from_secs(30),
                multiplier: 2.0,
            },
        }
    }
}

/// Retry strategy for failed connections
#[derive(Debug, Clone)]
pub enum RetryStrategy {
    ExponentialBackoff {
        initial_delay: Duration,
        max_delay: Duration,
        multiplier: f64,
    },
    FixedInterval(Duration),
    NoRetry,
}

/// Peer status in the mesh network
#[derive(Debug, Clone)]
pub struct PeerStatus {
    pub peer_id: PeerId,
    pub addresses: Vec<SocketAddr>,
    pub connection_count: usize,
    pub latency_ms: f64,
    pub last_seen: Instant,
    pub connection_state: PeerConnectionState,
}

/// Connection state for a peer
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    Failed,
}

/// Events emitted by the mesh endpoint
#[derive(Debug, Clone)]
pub enum PeerEvent {
    Connected(PeerId),
    Disconnected(PeerId),
    LatencyChanged { peer_id: PeerId, latency: Duration },
    ConnectionFailed { peer_id: PeerId, error: String },
    DataReceived { peer_id: PeerId, data: Bytes },
}

/// DERP server configuration for NAT traversal
#[derive(Debug, Clone)]
pub struct DerpConfig {
    pub servers: Vec<DerpServer>,
    pub region_preference: RegionPreference,
    pub fallback_strategy: DerpFallbackStrategy,
}

impl Default for DerpConfig {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            region_preference: RegionPreference::LowestLatency,
            fallback_strategy: DerpFallbackStrategy::Automatic,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DerpServer {
    pub url: String,
    pub region: String,
    pub latency_ms: Option<f64>,
}

#[derive(Debug, Clone)]
pub enum RegionPreference {
    LowestLatency,
    Geographic(String),
    Specific(Vec<String>),
}

#[derive(Debug, Clone)]
pub enum DerpFallbackStrategy {
    Automatic,
    Manual,
    Disabled,
}

/// Service discovery configuration
#[derive(Debug, Clone)]
pub struct ServiceDiscoveryConfig {
    pub mdns: bool,
    pub dns_sd: bool,
    pub derp_coordination: bool,
    pub discovery_interval: Duration,
}

impl Default for ServiceDiscoveryConfig {
    fn default() -> Self {
        Self {
            mdns: true,
            dns_sd: true,
            derp_coordination: true,
            discovery_interval: Duration::from_secs(30),
        }
    }
}

/// Mesh endpoint configuration
#[derive(Debug, Clone)]
pub struct MeshConfig {
    pub peer_id: PeerId,
    pub listen_addr: SocketAddr,
    pub connection_strategy: ConnectionStrategy,
    pub derp_config: Option<DerpConfig>,
    pub service_discovery: ServiceDiscoveryConfig,
    pub max_peers: usize,
    pub keepalive_interval: Duration,
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            peer_id: PeerId::generate(),
            listen_addr: "0.0.0.0:0".parse().unwrap(),
            connection_strategy: ConnectionStrategy::default(),
            derp_config: None,
            service_discovery: ServiceDiscoveryConfig::default(),
            max_peers: 100,
            keepalive_interval: Duration::from_secs(30),
        }
    }
}

/// Main mesh networking endpoint - the core of GQUIC's mesh capabilities
#[derive(Debug)]
pub struct GQuicMeshEndpoint {
    config: MeshConfig,
    socket: Arc<UdpSocket>,
    peers: Arc<RwLock<HashMap<PeerId, PeerConnection>>>,
    event_tx: mpsc::UnboundedSender<PeerEvent>,
    event_rx: Arc<Mutex<mpsc::UnboundedReceiver<PeerEvent>>>,
    discovery_handle: Option<tokio::task::JoinHandle<()>>,
}

/// Internal peer connection management
#[derive(Debug)]
struct PeerConnection {
    peer_id: PeerId,
    addresses: Vec<SocketAddr>,
    connections: Vec<Connection>,
    status: PeerStatus,
    last_ping: Instant,
}

impl GQuicMeshEndpoint {
    /// Create a new mesh endpoint
    pub async fn new(config: MeshConfig) -> Result<Self> {
        let socket = UdpSocket::bind(config.listen_addr).await
            .map_err(|e| QuicError::Io(e.to_string()))?;

        let local_addr = socket.local_addr()
            .map_err(|e| QuicError::Io(e.to_string()))?;

        info!("GQUIC Mesh endpoint created for peer {} on {}",
              config.peer_id, local_addr);

        let (event_tx, event_rx) = mpsc::unbounded_channel();

        Ok(Self {
            config,
            socket: Arc::new(socket),
            peers: Arc::new(RwLock::new(HashMap::new())),
            event_tx,
            event_rx: Arc::new(Mutex::new(event_rx)),
            discovery_handle: None,
        })
    }

    /// Add a peer to the mesh network
    pub async fn add_peer(&mut self, peer_id: PeerId, addresses: Vec<SocketAddr>) -> Result<()> {
        debug!("Adding peer {} with {} addresses", peer_id, addresses.len());

        let peer_connection = PeerConnection {
            peer_id: peer_id.clone(),
            addresses: addresses.clone(),
            connections: Vec::new(),
            status: PeerStatus {
                peer_id: peer_id.clone(),
                addresses,
                connection_count: 0,
                latency_ms: 0.0,
                last_seen: Instant::now(),
                connection_state: PeerConnectionState::Disconnected,
            },
            last_ping: Instant::now(),
        };

        self.peers.write().await.insert(peer_id.clone(), peer_connection);

        // Attempt to connect to the peer
        self.connect_to_peer(peer_id).await?;

        Ok(())
    }

    /// Enable automatic peer discovery
    pub async fn enable_auto_discovery(&mut self, derp_servers: Vec<DerpServer>) -> Result<()> {
        info!("Enabling auto-discovery with {} DERP servers", derp_servers.len());

        // Store DERP configuration
        self.config.derp_config = Some(DerpConfig {
            servers: derp_servers,
            region_preference: RegionPreference::LowestLatency,
            fallback_strategy: DerpFallbackStrategy::Automatic,
        });

        // Start discovery task
        let discovery_handle = self.start_discovery_task().await;
        self.discovery_handle = Some(discovery_handle);

        Ok(())
    }

    /// Connect to a specific peer
    async fn connect_to_peer(&self, peer_id: PeerId) -> Result<()> {
        debug!("Attempting to connect to peer {}", peer_id);

        let peers = self.peers.read().await;
        let peer = peers.get(&peer_id)
            .ok_or_else(|| QuicError::Protocol(crate::quic::error::ProtocolError::InvalidPacketFormat(format!("Peer {} not found", peer_id))))?;

        // Try each address in order
        for addr in &peer.addresses {
            match self.attempt_connection(*addr).await {
                Ok(connection) => {
                    debug!("Successfully connected to peer {} at {}", peer_id, addr);

                    // Update peer status
                    drop(peers); // Release read lock
                    let mut peers = self.peers.write().await;
                    if let Some(peer) = peers.get_mut(&peer_id) {
                        peer.connections.push(connection);
                        peer.status.connection_count = peer.connections.len();
                        peer.status.connection_state = PeerConnectionState::Connected;
                    }

                    // Emit connection event
                    let _ = self.event_tx.send(PeerEvent::Connected(peer_id));
                    return Ok(());
                }
                Err(e) => {
                    warn!("Failed to connect to {} at {}: {}", peer_id, addr, e);
                    continue;
                }
            }
        }

        // All connection attempts failed
        let error_msg = format!("All connection attempts to {} failed", peer_id);
        let _ = self.event_tx.send(PeerEvent::ConnectionFailed {
            peer_id: peer_id.clone(),
            error: error_msg.clone(),
        });

        Err(QuicError::Protocol(crate::quic::error::ProtocolError::InvalidPacketFormat(error_msg)))
    }

    /// Attempt connection to a specific address
    async fn attempt_connection(&self, addr: SocketAddr) -> Result<Connection> {
        // For now, create a simple connection
        // In a full implementation, this would handle the full QUIC handshake
        let connection_id = ConnectionId::new();
        let connection = Connection::new(connection_id, addr, self.socket.clone(), true);
        Ok(connection)
    }

    /// Get peer status
    pub async fn get_peer_status(&self, peer_id: &PeerId) -> Option<PeerStatus> {
        let peers = self.peers.read().await;
        peers.get(peer_id).map(|p| p.status.clone())
    }

    /// Get events stream
    pub async fn peer_events(&self) -> mpsc::UnboundedReceiver<PeerEvent> {
        // In a real implementation, this would create a new receiver
        // For now, return a dummy receiver
        let (_, rx) = mpsc::unbounded_channel();
        rx
    }

    /// Send data to a peer
    pub async fn send_to_peer(&self, peer_id: &PeerId, data: Bytes) -> Result<()> {
        debug!("Sending {} bytes to peer {}", data.len(), peer_id);

        let peers = self.peers.read().await;
        let peer = peers.get(peer_id)
            .ok_or_else(|| QuicError::Protocol(crate::quic::error::ProtocolError::InvalidPacketFormat(format!("Peer {} not found", peer_id))))?;

        if peer.connections.is_empty() {
            return Err(QuicError::Protocol(crate::quic::error::ProtocolError::InvalidState(format!("No connections to peer {}", peer_id))));
        }

        // Send on the first available connection
        // In a real implementation, this would use load balancing
        let connection = &peer.connections[0];
        connection.send_data(&data).await?;

        Ok(())
    }

    /// Start peer discovery background task
    async fn start_discovery_task(&self) -> tokio::task::JoinHandle<()> {
        let peers = Arc::clone(&self.peers);
        let event_tx = self.event_tx.clone();
        let discovery_config = self.config.service_discovery.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(discovery_config.discovery_interval);

            loop {
                interval.tick().await;

                // Perform peer discovery
                if discovery_config.mdns {
                    // mDNS discovery logic would go here
                    debug!("Performing mDNS discovery");
                }

                if discovery_config.dns_sd {
                    // DNS-SD discovery logic would go here
                    debug!("Performing DNS-SD discovery");
                }

                if discovery_config.derp_coordination {
                    // DERP coordination logic would go here
                    debug!("Performing DERP coordination");
                }

                // Update peer latencies
                let peers_read = peers.read().await;
                for (peer_id, peer) in peers_read.iter() {
                    // Simulate latency measurement
                    let latency = Duration::from_millis(50); // Placeholder
                    let _ = event_tx.send(PeerEvent::LatencyChanged {
                        peer_id: peer_id.clone(),
                        latency,
                    });
                }
            }
        })
    }

    /// Get network topology information
    pub async fn get_network_topology(&self) -> NetworkTopology {
        let peers = self.peers.read().await;
        let mut nodes = Vec::new();
        let mut edges = Vec::new();

        // Add self as a node
        nodes.push(TopologyNode {
            peer_id: self.config.peer_id.clone(),
            address: self.socket.local_addr().ok(),
            peer_type: NodeType::Self_,
        });

        // Add peer nodes and edges
        for (peer_id, peer) in peers.iter() {
            nodes.push(TopologyNode {
                peer_id: peer_id.clone(),
                address: peer.addresses.first().copied(),
                peer_type: NodeType::Peer,
            });

            if !peer.connections.is_empty() {
                edges.push(TopologyEdge {
                    from: self.config.peer_id.clone(),
                    to: peer_id.clone(),
                    connection_count: peer.connections.len(),
                    latency_ms: peer.status.latency_ms,
                });
            }
        }

        NetworkTopology { nodes, edges }
    }

    /// Get comprehensive metrics
    pub async fn get_metrics(&self) -> MeshMetrics {
        let peers = self.peers.read().await;
        let total_peers = peers.len();
        let connected_peers = peers.values()
            .filter(|p| p.status.connection_state == PeerConnectionState::Connected)
            .count();

        let total_connections: usize = peers.values()
            .map(|p| p.connections.len())
            .sum();

        let average_latency = peers.values()
            .map(|p| p.status.latency_ms)
            .sum::<f64>() / peers.len() as f64;

        MeshMetrics {
            total_peers,
            connected_peers,
            total_connections,
            average_latency_ms: average_latency,
            throughput_mbps: 0.0, // Placeholder
            packet_loss_percent: 0.0, // Placeholder
            uptime_seconds: 0, // Placeholder
        }
    }

    /// Resolve peer by hostname (MagicDNS)
    pub async fn resolve_peer(&self, hostname: &str) -> Result<SocketAddr> {
        // Simplified MagicDNS resolution
        // In a real implementation, this would integrate with a DNS resolver

        debug!("Resolving hostname: {}", hostname);

        // Try to parse as direct IP first
        if let Ok(addr) = hostname.parse::<SocketAddr>() {
            return Ok(addr);
        }

        // Check if it's a known peer hostname
        let peers = self.peers.read().await;
        for peer in peers.values() {
            if hostname.contains(&peer.peer_id.0) {
                if let Some(addr) = peer.addresses.first() {
                    return Ok(*addr);
                }
            }
        }

        Err(QuicError::Protocol(crate::quic::error::ProtocolError::InvalidState(format!("Cannot resolve hostname: {}", hostname))))
    }

    /// Shutdown the mesh endpoint
    pub async fn shutdown(&mut self) -> Result<()> {
        info!("Shutting down mesh endpoint for peer {}", self.config.peer_id);

        // Cancel discovery task
        if let Some(handle) = self.discovery_handle.take() {
            handle.abort();
        }

        // Close all peer connections
        let mut peers = self.peers.write().await;
        for (peer_id, peer) in peers.iter_mut() {
            for connection in &peer.connections {
                if let Err(e) = connection.close(0, "Mesh network shutdown").await {
                    warn!("Error closing connection to {}: {}", peer_id, e);
                }
            }
        }
        peers.clear();

        Ok(())
    }
}

/// Network topology representation
#[derive(Debug, Clone)]
pub struct NetworkTopology {
    pub nodes: Vec<TopologyNode>,
    pub edges: Vec<TopologyEdge>,
}

impl NetworkTopology {
    /// Export topology as Graphviz DOT format
    pub fn export_graphviz(&self, filename: &str) -> Result<()> {
        use std::fs::File;
        use std::io::Write;

        let mut file = File::create(filename)
            .map_err(|e| QuicError::Io(e.to_string()))?;

        writeln!(file, "digraph mesh_network {{")?;
        writeln!(file, "  rankdir=LR;")?;

        // Write nodes
        for node in &self.nodes {
            let color = match node.peer_type {
                NodeType::Self_ => "red",
                NodeType::Peer => "blue",
            };
            writeln!(file, "  \"{}\" [color={}];", node.peer_id, color)?;
        }

        // Write edges
        for edge in &self.edges {
            writeln!(file, "  \"{}\" -> \"{}\" [label=\"{} conn, {:.1}ms\"];",
                edge.from, edge.to, edge.connection_count, edge.latency_ms)?;
        }

        writeln!(file, "}}")?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct TopologyNode {
    pub peer_id: PeerId,
    pub address: Option<SocketAddr>,
    pub peer_type: NodeType,
}

#[derive(Debug, Clone)]
pub enum NodeType {
    Self_,
    Peer,
}

#[derive(Debug, Clone)]
pub struct TopologyEdge {
    pub from: PeerId,
    pub to: PeerId,
    pub connection_count: usize,
    pub latency_ms: f64,
}

/// Comprehensive mesh networking metrics
#[derive(Debug, Clone)]
pub struct MeshMetrics {
    pub total_peers: usize,
    pub connected_peers: usize,
    pub total_connections: usize,
    pub average_latency_ms: f64,
    pub throughput_mbps: f64,
    pub packet_loss_percent: f64,
    pub uptime_seconds: u64,
}

// Convenience builder for mesh endpoints
pub struct GQuicMeshEndpointBuilder {
    config: MeshConfig,
}

impl GQuicMeshEndpointBuilder {
    pub fn new() -> Self {
        Self {
            config: MeshConfig::default(),
        }
    }

    pub fn peer_id(mut self, peer_id: PeerId) -> Self {
        self.config.peer_id = peer_id;
        self
    }

    pub fn listen_addr(mut self, addr: SocketAddr) -> Self {
        self.config.listen_addr = addr;
        self
    }

    pub fn connection_strategy(mut self, strategy: ConnectionStrategy) -> Self {
        self.config.connection_strategy = strategy;
        self
    }

    pub fn max_peers(mut self, max_peers: usize) -> Self {
        self.config.max_peers = max_peers;
        self
    }

    pub async fn build(self) -> Result<GQuicMeshEndpoint> {
        GQuicMeshEndpoint::new(self.config).await
    }
}

impl Default for GQuicMeshEndpointBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mesh_endpoint_creation() {
        let config = MeshConfig::default();
        let endpoint = GQuicMeshEndpoint::new(config).await.unwrap();

        assert_eq!(endpoint.config.max_peers, 100);
    }

    #[tokio::test]
    async fn test_peer_management() {
        let mut endpoint = GQuicMeshEndpoint::new(MeshConfig::default()).await.unwrap();

        let peer_id = PeerId::new("test-peer");
        let addresses = vec!["127.0.0.1:8080".parse().unwrap()];

        endpoint.add_peer(peer_id.clone(), addresses).await.unwrap();

        let status = endpoint.get_peer_status(&peer_id).await;
        assert!(status.is_some());
    }

    #[tokio::test]
    async fn test_builder_pattern() {
        let peer_id = PeerId::new("builder-test");
        let addr = "127.0.0.1:9000".parse().unwrap();

        let endpoint = GQuicMeshEndpointBuilder::new()
            .peer_id(peer_id.clone())
            .listen_addr(addr)
            .max_peers(50)
            .build()
            .await
            .unwrap();

        assert_eq!(endpoint.config.peer_id, peer_id);
        assert_eq!(endpoint.config.max_peers, 50);
    }
}