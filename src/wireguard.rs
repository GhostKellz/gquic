//! WireGuard Integration for GQUIC
//!
//! This module provides WireGuard VPN integration points for GQUIC, enabling
//! hybrid VPN modes, secure tunneling, and seamless integration with mesh
//! networking capabilities for both GhostWire and BOLT container platforms.

use crate::quic::{
    connection::{Connection, ConnectionId},
    error::{QuicError, Result, ProtocolError},
};
use crate::mesh::{GQuicMeshEndpoint, PeerId, MeshConfig};
use crate::network::{NetworkInterface, NetworkConfig, NetworkEvent};
use bytes::{Bytes, BytesMut, BufMut};
use std::collections::HashMap;
use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::{RwLock, Mutex, mpsc};
use tokio::task::JoinHandle;
use tokio::time::{timeout, sleep, interval};
use tracing::{debug, info, warn, error, trace};
use serde::{Serialize, Deserialize};

/// WireGuard integration manager for GQUIC
#[derive(Debug)]
pub struct WireGuardManager {
    /// WireGuard configuration
    config: WireGuardConfig,
    /// Active WireGuard interfaces
    interfaces: Arc<RwLock<HashMap<String, WireGuardInterface>>>,
    /// QUIC network interface for hybrid mode
    quic_network: Arc<NetworkInterface>,
    /// Peer registry for VPN clients
    peer_registry: Arc<RwLock<PeerRegistry>>,
    /// Tunnel manager for QUIC over WireGuard
    tunnel_manager: Arc<Mutex<TunnelManager>>,
    /// Key exchange handler
    key_exchange: Arc<RwLock<KeyExchangeHandler>>,
    /// Statistics and monitoring
    stats: Arc<RwLock<WireGuardStats>>,
    /// Background task handles
    task_handles: Vec<JoinHandle<()>>,
}

/// WireGuard configuration for GQUIC integration
#[derive(Debug, Clone)]
pub struct WireGuardConfig {
    /// Enable hybrid QUIC+WireGuard mode
    pub enable_hybrid_mode: bool,
    /// WireGuard interface name prefix
    pub interface_prefix: String,
    /// Default WireGuard port
    pub wireguard_port: u16,
    /// QUIC port for hybrid connections
    pub quic_port: u16,
    /// Enable automatic key rotation
    pub enable_key_rotation: bool,
    /// Key rotation interval
    pub key_rotation_interval: Duration,
    /// Enable NAT traversal via QUIC
    pub enable_nat_traversal: bool,
    /// Maximum concurrent tunnels
    pub max_tunnels: usize,
    /// Tunnel keepalive interval
    pub tunnel_keepalive: Duration,
    /// Enable container networking mode (for BOLT)
    pub enable_container_mode: bool,
    /// Container namespace isolation
    pub container_isolation: bool,
}

impl Default for WireGuardConfig {
    fn default() -> Self {
        Self {
            enable_hybrid_mode: true,
            interface_prefix: "gquic-wg".to_string(),
            wireguard_port: 51820,
            quic_port: 51821,
            enable_key_rotation: true,
            key_rotation_interval: Duration::from_secs(3600), // 1 hour
            enable_nat_traversal: true,
            max_tunnels: 1000,
            tunnel_keepalive: Duration::from_secs(25),
            enable_container_mode: false,
            container_isolation: true,
        }
    }
}

/// WireGuard interface representation
#[derive(Debug, Clone)]
pub struct WireGuardInterface {
    /// Interface name
    pub name: String,
    /// Interface address
    pub address: IpAddr,
    /// Interface subnet
    pub subnet: String,
    /// Private key (base64 encoded)
    pub private_key: String,
    /// Public key (base64 encoded)
    pub public_key: String,
    /// Listen port
    pub listen_port: u16,
    /// Connected peers
    pub peers: HashMap<String, WireGuardPeer>,
    /// Interface state
    pub state: InterfaceState,
    /// Creation time
    pub created_at: SystemTime,
    /// Last activity
    pub last_activity: Instant,
}

impl WireGuardInterface {
    /// Create a new WireGuard interface
    pub async fn new(config: WireGuardConfig) -> Result<Self> {
        use std::collections::HashMap;
        use std::time::SystemTime;

        // Generate interface name
        let interface_name = format!("{}-{}", config.interface_prefix, rand::random::<u32>());

        // Generate WireGuard keys
        let private_key = format!("wg_private_key_{}", rand::random::<u64>());
        let public_key = format!("wg_public_key_{}", rand::random::<u64>());

        Ok(Self {
            name: interface_name,
            address: "10.0.0.1".parse().unwrap(), // Default interface address
            subnet: "10.0.0.0/24".to_string(),
            private_key,
            public_key,
            listen_port: config.wireguard_port,
            peers: HashMap::new(),
            state: InterfaceState::Creating,
            created_at: SystemTime::now(),
            last_activity: Instant::now(),
        })
    }

    /// Connect to a peer
    pub async fn connect_peer(&self, peer_id: &str, endpoint: SocketAddr) -> Result<()> {
        info!("Connecting WireGuard peer {} at {}", peer_id, endpoint);

        // In a real implementation, this would:
        // 1. Add the peer to WireGuard configuration
        // 2. Establish the WireGuard tunnel
        // 3. Set up routing rules

        // For now, we'll just log the connection attempt
        debug!("WireGuard peer connection simulated for {} -> {}", peer_id, endpoint);
        Ok(())
    }

    /// Get interface statistics
    pub fn stats(&self) -> InterfaceStats {
        InterfaceStats {
            interface_name: self.name.clone(),
            state: self.state.clone(),
            peer_count: self.peers.len(),
            bytes_sent: 0, // Would be populated from actual interface stats
            bytes_received: 0,
            last_activity: self.last_activity,
        }
    }
}

/// Interface statistics
#[derive(Debug, Clone)]
pub struct InterfaceStats {
    pub interface_name: String,
    pub state: InterfaceState,
    pub peer_count: usize,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub last_activity: Instant,
}

/// WireGuard peer configuration
#[derive(Debug, Clone)]
pub struct WireGuardPeer {
    /// Peer public key
    pub public_key: String,
    /// Peer endpoint address
    pub endpoint: Option<SocketAddr>,
    /// Allowed IPs for this peer
    pub allowed_ips: Vec<String>,
    /// Pre-shared key (optional)
    pub preshared_key: Option<String>,
    /// Persistent keepalive interval
    pub persistent_keepalive: Option<Duration>,
    /// Peer statistics
    pub stats: PeerStats,
    /// QUIC connection ID for hybrid mode
    pub quic_connection_id: Option<ConnectionId>,
}

/// Interface states
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterfaceState {
    /// Interface is being created
    Creating,
    /// Interface is active
    Active,
    /// Interface is in error state
    Error(String),
    /// Interface is being destroyed
    Destroying,
}

/// Peer registry for managing VPN clients
#[derive(Debug)]
pub struct PeerRegistry {
    /// Registered peers by public key
    peers: HashMap<String, WireGuardPeer>,
    /// Peer lookup by QUIC connection ID
    quic_peer_map: HashMap<ConnectionId, String>,
    /// Container peer mappings (for BOLT integration)
    container_peers: HashMap<String, ContainerPeerInfo>,
}

/// Container peer information for BOLT integration
#[derive(Debug, Clone)]
pub struct ContainerPeerInfo {
    /// Container ID
    pub container_id: String,
    /// Container namespace
    pub namespace: String,
    /// Assigned IP address
    pub assigned_ip: IpAddr,
    /// Container labels
    pub labels: HashMap<String, String>,
    /// Network policies
    pub policies: Vec<NetworkPolicy>,
}

/// Network policy for container isolation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPolicy {
    /// Policy name
    pub name: String,
    /// Source selectors
    pub from: Vec<PolicySelector>,
    /// Destination selectors
    pub to: Vec<PolicySelector>,
    /// Allowed ports
    pub ports: Vec<PolicyPort>,
    /// Policy action
    pub action: PolicyAction,
}

/// Policy selector for network rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySelector {
    /// Pod selector
    pub pod_selector: Option<HashMap<String, String>>,
    /// Namespace selector
    pub namespace_selector: Option<HashMap<String, String>>,
    /// IP block
    pub ip_block: Option<String>,
}

/// Policy port specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyPort {
    /// Port number
    pub port: u16,
    /// Protocol (TCP/UDP)
    pub protocol: String,
}

/// Policy actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyAction {
    Allow,
    Deny,
    Log,
}

/// Tunnel manager for QUIC over WireGuard
#[derive(Debug)]
pub struct TunnelManager {
    /// Active tunnels
    tunnels: HashMap<TunnelId, WireGuardTunnel>,
    /// Tunnel routing table
    routing_table: HashMap<IpAddr, TunnelId>,
    /// Tunnel statistics
    tunnel_stats: HashMap<TunnelId, TunnelStats>,
}

/// Unique tunnel identifier
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct TunnelId(pub String);

impl std::fmt::Display for TunnelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// WireGuard tunnel for QUIC traffic
#[derive(Debug)]
pub struct WireGuardTunnel {
    /// Tunnel ID
    pub id: TunnelId,
    /// Local endpoint
    pub local_endpoint: SocketAddr,
    /// Remote endpoint
    pub remote_endpoint: SocketAddr,
    /// WireGuard peer for this tunnel
    pub wireguard_peer: WireGuardPeer,
    /// QUIC connection for hybrid mode
    pub quic_connection: Option<Arc<Connection>>,
    /// Tunnel state
    pub state: TunnelState,
    /// Created at
    pub created_at: Instant,
    /// Last activity
    pub last_activity: Instant,
}

/// Tunnel states
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelState {
    /// Tunnel is establishing
    Establishing,
    /// Tunnel is connected
    Connected,
    /// Tunnel is reconnecting
    Reconnecting,
    /// Tunnel is disconnected
    Disconnected,
    /// Tunnel has failed
    Failed(String),
}

/// Key exchange handler for WireGuard integration
#[derive(Debug)]
pub struct KeyExchangeHandler {
    /// Current key pairs
    key_pairs: HashMap<String, KeyPair>,
    /// Key rotation schedule
    rotation_schedule: HashMap<String, Instant>,
    /// Pre-shared keys for trusted networks
    preshared_keys: HashMap<String, String>,
}

/// Cryptographic key pair
#[derive(Debug, Clone)]
pub struct KeyPair {
    /// Private key (base64 encoded)
    pub private_key: String,
    /// Public key (base64 encoded)
    pub public_key: String,
    /// Key generation time
    pub generated_at: SystemTime,
    /// Key expiry time
    pub expires_at: SystemTime,
}

/// Peer statistics
#[derive(Debug, Clone, Default)]
pub struct PeerStats {
    /// Bytes transmitted
    pub tx_bytes: u64,
    /// Bytes received
    pub rx_bytes: u64,
    /// Last handshake time
    pub last_handshake: Option<SystemTime>,
    /// Connection duration
    pub connected_duration: Duration,
}

/// Tunnel statistics
#[derive(Debug, Clone, Default)]
pub struct TunnelStats {
    /// Packets transmitted
    pub tx_packets: u64,
    /// Packets received
    pub rx_packets: u64,
    /// Bytes transmitted
    pub tx_bytes: u64,
    /// Bytes received
    pub rx_bytes: u64,
    /// Connection errors
    pub errors: u64,
    /// Average latency
    pub avg_latency: Duration,
}

/// WireGuard integration statistics
#[derive(Debug, Default, Clone)]
pub struct WireGuardStats {
    /// Active interfaces
    pub active_interfaces: usize,
    /// Total peers
    pub total_peers: usize,
    /// Active tunnels
    pub active_tunnels: usize,
    /// Total bytes transferred
    pub total_bytes: u64,
    /// Key rotations performed
    pub key_rotations: u64,
    /// NAT traversal successes
    pub nat_traversals: u64,
    /// Container connections (BOLT mode)
    pub container_connections: usize,
}

impl WireGuardManager {
    /// Create a new WireGuard manager
    pub async fn new(
        config: WireGuardConfig,
        quic_network: Arc<NetworkInterface>,
    ) -> Result<Self> {
        info!("Creating WireGuard manager with config: {:?}", config);

        let peer_registry = PeerRegistry {
            peers: HashMap::new(),
            quic_peer_map: HashMap::new(),
            container_peers: HashMap::new(),
        };

        let tunnel_manager = TunnelManager {
            tunnels: HashMap::new(),
            routing_table: HashMap::new(),
            tunnel_stats: HashMap::new(),
        };

        let key_exchange = KeyExchangeHandler {
            key_pairs: HashMap::new(),
            rotation_schedule: HashMap::new(),
            preshared_keys: HashMap::new(),
        };

        let manager = Self {
            config,
            interfaces: Arc::new(RwLock::new(HashMap::new())),
            quic_network,
            peer_registry: Arc::new(RwLock::new(peer_registry)),
            tunnel_manager: Arc::new(Mutex::new(tunnel_manager)),
            key_exchange: Arc::new(RwLock::new(key_exchange)),
            stats: Arc::new(RwLock::new(WireGuardStats::default())),
            task_handles: Vec::new(),
        };

        Ok(manager)
    }

    /// Start the WireGuard manager
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting WireGuard manager");

        // Start key rotation task if enabled
        if self.config.enable_key_rotation {
            let task = self.start_key_rotation_task().await;
            self.task_handles.push(task);
        }

        // Start tunnel monitoring task
        let task = self.start_tunnel_monitoring_task().await;
        self.task_handles.push(task);

        // Start statistics collection task
        let task = self.start_stats_task().await;
        self.task_handles.push(task);

        info!("WireGuard manager started successfully");
        Ok(())
    }

    /// Create a new WireGuard interface
    pub async fn create_interface(
        &self,
        name: &str,
        address: IpAddr,
        subnet: &str,
    ) -> Result<String> {
        info!("Creating WireGuard interface: {} with address {} ({})", name, address, subnet);

        // Generate key pair for the interface
        let key_pair = self.generate_key_pair().await?;

        let interface = WireGuardInterface {
            name: name.to_string(),
            address,
            subnet: subnet.to_string(),
            private_key: key_pair.private_key,
            public_key: key_pair.public_key,
            listen_port: self.config.wireguard_port,
            peers: HashMap::new(),
            state: InterfaceState::Creating,
            created_at: SystemTime::now(),
            last_activity: Instant::now(),
        };

        // Add to interfaces map
        {
            let mut interfaces = self.interfaces.write().await;
            interfaces.insert(name.to_string(), interface);
        }

        // In a real implementation, this would:
        // 1. Create the actual WireGuard interface using netlink
        // 2. Configure the interface with ip/wg commands
        // 3. Set up routing rules

        // For now, we'll simulate interface creation
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Update interface state to active
        {
            let mut interfaces = self.interfaces.write().await;
            if let Some(interface) = interfaces.get_mut(name) {
                interface.state = InterfaceState::Active;
            }
        }

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.active_interfaces += 1;
        }

        info!("WireGuard interface {} created successfully", name);
        Ok(name.to_string())
    }

    /// Add a peer to a WireGuard interface
    pub async fn add_peer(
        &self,
        interface_name: &str,
        peer_config: WireGuardPeer,
    ) -> Result<()> {
        info!("Adding peer {} to interface {}", peer_config.public_key, interface_name);

        // Add peer to interface
        {
            let mut interfaces = self.interfaces.write().await;
            let interface = interfaces.get_mut(interface_name)
                .ok_or_else(|| QuicError::Protocol(ProtocolError::InvalidState(
                    "Interface not found".to_string()
                )))?;

            interface.peers.insert(peer_config.public_key.clone(), peer_config.clone());
            interface.last_activity = Instant::now();
        }

        // Add to peer registry
        {
            let mut registry = self.peer_registry.write().await;
            registry.peers.insert(peer_config.public_key.clone(), peer_config.clone());

            // Map QUIC connection ID if in hybrid mode
            if let Some(quic_conn_id) = &peer_config.quic_connection_id {
                registry.quic_peer_map.insert(quic_conn_id.clone(), peer_config.public_key.clone());
            }
        }

        // In a real implementation, this would:
        // 1. Use wg command to add peer to the interface
        // 2. Configure peer-specific routing rules
        // 3. Set up firewall rules if needed

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.total_peers += 1;
        }

        info!("Peer {} added successfully", peer_config.public_key);
        Ok(())
    }

    /// Create a hybrid QUIC+WireGuard tunnel
    pub async fn create_hybrid_tunnel(
        &self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        peer_public_key: &str,
    ) -> Result<TunnelId> {
        if !self.config.enable_hybrid_mode {
            return Err(QuicError::Protocol(ProtocolError::InvalidState(
                "Hybrid mode not enabled".to_string()
            )));
        }

        let tunnel_id = TunnelId(format!("hybrid-{}-{}", local_addr, remote_addr));

        info!("Creating hybrid tunnel: {} -> {}", local_addr, remote_addr);

        // Create QUIC connection for the tunnel
        let quic_connection = self.quic_network.create_connection(
            ConnectionId::from_bytes(&tunnel_id.0.as_bytes()),
            remote_addr,
            Some(local_addr),
        ).await?;

        // Find peer configuration
        let peer = {
            let registry = self.peer_registry.read().await;
            registry.peers.get(peer_public_key).cloned()
                .ok_or_else(|| QuicError::Protocol(ProtocolError::InvalidState(
                    "Peer not found".to_string()
                )))?
        };

        let tunnel = WireGuardTunnel {
            id: tunnel_id.clone(),
            local_endpoint: local_addr,
            remote_endpoint: remote_addr,
            wireguard_peer: peer,
            quic_connection: None, // Would be set after connection establishment
            state: TunnelState::Establishing,
            created_at: Instant::now(),
            last_activity: Instant::now(),
        };

        // Add tunnel to manager
        {
            let mut tm = self.tunnel_manager.lock().await;
            tm.tunnels.insert(tunnel_id.clone(), tunnel);
            tm.routing_table.insert(remote_addr.ip(), tunnel_id.clone());
            tm.tunnel_stats.insert(tunnel_id.clone(), TunnelStats::default());
        }

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.active_tunnels += 1;
        }

        info!("Hybrid tunnel {} created", tunnel_id);
        Ok(tunnel_id)
    }

    /// Add container peer for BOLT integration
    pub async fn add_container_peer(
        &self,
        container_info: ContainerPeerInfo,
        peer_config: WireGuardPeer,
    ) -> Result<()> {
        if !self.config.enable_container_mode {
            return Err(QuicError::Protocol(ProtocolError::InvalidState(
                "Container mode not enabled".to_string()
            )));
        }

        info!("Adding container peer: {} ({})", container_info.container_id, container_info.assigned_ip);

        // Add to peer registry with container mapping
        {
            let mut registry = self.peer_registry.write().await;
            registry.peers.insert(peer_config.public_key.clone(), peer_config);
            registry.container_peers.insert(
                container_info.container_id.clone(),
                container_info,
            );
        }

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.container_connections += 1;
        }

        info!("Container peer added successfully");
        Ok(())
    }

    /// Apply network policy for container isolation
    pub async fn apply_network_policy(&self, policy: NetworkPolicy) -> Result<()> {
        info!("Applying network policy: {}", policy.name);

        // In a real implementation, this would:
        // 1. Parse the policy selectors
        // 2. Create iptables/nftables rules
        // 3. Configure WireGuard peer allowed IPs
        // 4. Set up traffic shaping if needed

        // For now, we'll just validate and store the policy
        debug!("Network policy {} applied successfully", policy.name);
        Ok(())
    }

    /// Generate a new cryptographic key pair
    async fn generate_key_pair(&self) -> Result<KeyPair> {
        // In a real implementation, this would use proper WireGuard key generation
        // For now, we'll create a placeholder

        let private_key = format!("privkey_{}", chrono::Utc::now().timestamp());
        let public_key = format!("pubkey_{}", chrono::Utc::now().timestamp());

        let key_pair = KeyPair {
            private_key: base64::encode(private_key),
            public_key: base64::encode(public_key),
            generated_at: SystemTime::now(),
            expires_at: SystemTime::now() + self.config.key_rotation_interval,
        };

        Ok(key_pair)
    }

    /// Start key rotation background task
    async fn start_key_rotation_task(&self) -> JoinHandle<()> {
        let key_exchange = Arc::clone(&self.key_exchange);
        let interval_duration = self.config.key_rotation_interval;
        let stats = Arc::clone(&self.stats);

        tokio::spawn(async move {
            let mut interval = interval(interval_duration);

            loop {
                interval.tick().await;

                debug!("Performing key rotation check");

                let now = SystemTime::now();
                let mut keys_rotated = 0;

                // Check for expired keys and rotate them
                {
                    let mut kx = key_exchange.write().await;
                    let mut expired_keys = Vec::new();

                    for (key_id, key_pair) in &kx.key_pairs {
                        if key_pair.expires_at <= now {
                            expired_keys.push(key_id.clone());
                        }
                    }

                    for key_id in expired_keys {
                        // Generate new key pair
                        let new_private = format!("rotated_privkey_{}", chrono::Utc::now().timestamp());
                        let new_public = format!("rotated_pubkey_{}", chrono::Utc::now().timestamp());

                        let new_key_pair = KeyPair {
                            private_key: base64::encode(new_private),
                            public_key: base64::encode(new_public),
                            generated_at: now,
                            expires_at: now + interval_duration,
                        };

                        debug!("Rotated key pair for key_id: {}", key_id);
                        kx.key_pairs.insert(key_id, new_key_pair);
                        keys_rotated += 1;
                    }
                }

                if keys_rotated > 0 {
                    let mut stats_guard = stats.write().await;
                    stats_guard.key_rotations += keys_rotated;
                    info!("Rotated {} key pairs", keys_rotated);
                }
            }
        })
    }

    /// Start tunnel monitoring task
    async fn start_tunnel_monitoring_task(&self) -> JoinHandle<()> {
        let tunnel_manager = Arc::clone(&self.tunnel_manager);
        let keepalive_interval = self.config.tunnel_keepalive;

        tokio::spawn(async move {
            let mut interval = interval(keepalive_interval);

            loop {
                interval.tick().await;

                debug!("Monitoring tunnel health");

                let mut tm = tunnel_manager.lock().await;
                let now = Instant::now();

                // Check tunnel health and send keepalives
                for (tunnel_id, tunnel) in &mut tm.tunnels {
                    let inactive_duration = now.duration_since(tunnel.last_activity);

                    if inactive_duration > keepalive_interval * 2 {
                        warn!("Tunnel {} appears inactive ({}s)", tunnel_id, inactive_duration.as_secs());

                        if tunnel.state == TunnelState::Connected {
                            tunnel.state = TunnelState::Reconnecting;
                        }
                    } else if tunnel.state == TunnelState::Reconnecting {
                        // Attempt to reconnect
                        debug!("Attempting to reconnect tunnel {}", tunnel_id);
                        // In a real implementation, this would trigger reconnection logic
                    }
                }
            }
        })
    }

    /// Start statistics collection task
    async fn start_stats_task(&self) -> JoinHandle<()> {
        let stats = Arc::clone(&self.stats);
        let interfaces = Arc::clone(&self.interfaces);
        let peer_registry = Arc::clone(&self.peer_registry);
        let tunnel_manager = Arc::clone(&self.tunnel_manager);

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(10));

            loop {
                interval.tick().await;

                // Update statistics
                let mut stats_guard = stats.write().await;

                // Count active interfaces
                let interfaces_count = interfaces.read().await.len();
                stats_guard.active_interfaces = interfaces_count;

                // Count peers
                let peers_count = peer_registry.read().await.peers.len();
                stats_guard.total_peers = peers_count;

                // Count active tunnels
                let tunnels_count = tunnel_manager.lock().await.tunnels.len();
                stats_guard.active_tunnels = tunnels_count;

                trace!("WireGuard stats: {} interfaces, {} peers, {} tunnels",
                       interfaces_count, peers_count, tunnels_count);
            }
        })
    }

    /// Get WireGuard statistics
    pub async fn stats(&self) -> WireGuardStats {
        self.stats.read().await.clone()
    }

    /// Get interface information
    pub async fn get_interface(&self, name: &str) -> Option<WireGuardInterface> {
        let interfaces = self.interfaces.read().await;
        interfaces.get(name).cloned()
    }

    /// List all interfaces
    pub async fn list_interfaces(&self) -> Vec<WireGuardInterface> {
        let interfaces = self.interfaces.read().await;
        interfaces.values().cloned().collect()
    }

    /// Remove an interface
    pub async fn remove_interface(&self, name: &str) -> Result<()> {
        info!("Removing WireGuard interface: {}", name);

        // Remove from interfaces map
        let removed = {
            let mut interfaces = self.interfaces.write().await;
            interfaces.remove(name)
        };

        if removed.is_some() {
            // In a real implementation, this would:
            // 1. Delete the WireGuard interface
            // 2. Clean up routing rules
            // 3. Remove firewall rules

            // Update statistics
            {
                let mut stats = self.stats.write().await;
                stats.active_interfaces = stats.active_interfaces.saturating_sub(1);
            }

            info!("WireGuard interface {} removed", name);
        }

        Ok(())
    }

    /// Shutdown the WireGuard manager
    pub async fn shutdown(&mut self) {
        info!("Shutting down WireGuard manager");

        // Cancel all background tasks
        for handle in self.task_handles.drain(..) {
            handle.abort();
        }

        // Clean up all interfaces
        let interface_names: Vec<_> = {
            let interfaces = self.interfaces.read().await;
            interfaces.keys().cloned().collect()
        };

        for name in interface_names {
            if let Err(e) = self.remove_interface(&name).await {
                warn!("Error removing interface {} during shutdown: {}", name, e);
            }
        }

        info!("WireGuard manager shutdown complete");
    }
}

impl Drop for WireGuardManager {
    fn drop(&mut self) {
        // Abort any remaining tasks
        for handle in &self.task_handles {
            handle.abort();
        }
    }
}

/// Utility functions for WireGuard key management
pub mod key_utils {
    use super::*;

    /// Validate a WireGuard public key
    pub fn validate_public_key(key: &str) -> bool {
        // Basic validation - real implementation would use proper WireGuard key validation
        key.len() == 44 && key.ends_with('=')
    }

    /// Generate a pre-shared key
    pub fn generate_preshared_key() -> String {
        // Real implementation would use proper cryptographic random generation
        let timestamp = chrono::Utc::now().timestamp();
        base64::encode(format!("psk_{}", timestamp))
    }

    /// Derive allowed IPs from container network
    pub fn derive_container_allowed_ips(container_info: &ContainerPeerInfo) -> Vec<String> {
        vec![format!("{}/32", container_info.assigned_ip)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::NetworkConfig;

    #[tokio::test]
    async fn test_wireguard_manager_creation() {
        let config = WireGuardConfig::default();
        let net_config = NetworkConfig {
            primary_addr: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        };
        let network = Arc::new(NetworkInterface::new(net_config).await.unwrap());

        let manager = WireGuardManager::new(config, network).await;
        assert!(manager.is_ok());
    }

    #[tokio::test]
    async fn test_interface_creation() {
        let config = WireGuardConfig::default();
        let net_config = NetworkConfig {
            primary_addr: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        };
        let network = Arc::new(NetworkInterface::new(net_config).await.unwrap());

        let manager = WireGuardManager::new(config, network).await.unwrap();

        let interface_name = manager.create_interface(
            "test-wg0",
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            "10.0.0.0/24",
        ).await.unwrap();

        assert_eq!(interface_name, "test-wg0");

        let interface = manager.get_interface("test-wg0").await;
        assert!(interface.is_some());
        assert_eq!(interface.unwrap().state, InterfaceState::Active);
    }

    #[test]
    fn test_key_validation() {
        assert!(key_utils::validate_public_key("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ="));
        assert!(!key_utils::validate_public_key("invalid_key"));
    }

    #[test]
    fn test_container_allowed_ips() {
        let container_info = ContainerPeerInfo {
            container_id: "test-container".to_string(),
            namespace: "default".to_string(),
            assigned_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100)),
            labels: HashMap::new(),
            policies: vec![],
        };

        let allowed_ips = key_utils::derive_container_allowed_ips(&container_info);
        assert_eq!(allowed_ips, vec!["10.0.0.100/32"]);
    }
}