//! Service Discovery and Peer Management for GQUIC
//!
//! This module provides comprehensive service discovery, peer management,
//! and dynamic network topology management for GQUIC mesh networks,
//! container orchestration, and distributed applications.

use crate::quic::{
    connection::{Connection, ConnectionId},
    error::{QuicError, Result, ProtocolError},
};
use crate::mesh::{GQuicMeshEndpoint, PeerId, MeshConfig};
use crate::derp::{DerpClient, DerpNodeInfo, DerpNodeId};
use crate::wireguard::{WireGuardManager, ContainerPeerInfo};
use bytes::{Bytes, BytesMut, BufMut};
use std::collections::{HashMap, HashSet, BTreeMap};
use std::net::{SocketAddr, IpAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, Mutex, broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio::time::{timeout, sleep, interval};
use tracing::{debug, info, warn, error, trace};
use serde::{Serialize, Deserialize};

/// Service discovery manager for GQUIC networks
#[derive(Debug)]
pub struct ServiceDiscoveryManager {
    /// Discovery configuration
    config: DiscoveryConfig,
    /// Local service registry
    local_services: Arc<RwLock<ServiceRegistry>>,
    /// Remote services cache
    remote_services: Arc<RwLock<RemoteServiceCache>>,
    /// Peer manager for network topology
    peer_manager: Arc<RwLock<PeerManager>>,
    /// Discovery protocols
    discovery_protocols: Arc<RwLock<HashMap<ProtocolType, Box<dyn DiscoveryProtocol>>>>,
    /// Event broadcaster
    event_broadcaster: broadcast::Sender<DiscoveryEvent>,
    /// Background task handles
    task_handles: Vec<JoinHandle<()>>,
    /// Statistics
    stats: Arc<RwLock<DiscoveryStats>>,
}

/// Service discovery configuration
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Local node ID
    pub node_id: String,
    /// Discovery announcement interval
    pub announcement_interval: Duration,
    /// Service TTL
    pub service_ttl: Duration,
    /// Peer discovery timeout
    pub discovery_timeout: Duration,
    /// Enable mDNS discovery
    pub enable_mdns: bool,
    /// Enable DNS-SD discovery
    pub enable_dns_sd: bool,
    /// Enable DHT-based discovery
    pub enable_dht: bool,
    /// Enable gossip protocol
    pub enable_gossip: bool,
    /// Maximum peers to maintain
    pub max_peers: usize,
    /// Container mode for BOLT integration
    pub container_mode: bool,
    /// Kubernetes integration
    pub kubernetes_integration: bool,
    /// Custom discovery endpoints
    pub custom_endpoints: Vec<SocketAddr>,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            node_id: uuid::Uuid::new_v4().to_string(),
            announcement_interval: Duration::from_secs(30),
            service_ttl: Duration::from_secs(300),
            discovery_timeout: Duration::from_secs(10),
            enable_mdns: true,
            enable_dns_sd: true,
            enable_dht: false,
            enable_gossip: true,
            max_peers: 1000,
            container_mode: false,
            kubernetes_integration: false,
            custom_endpoints: Vec::new(),
        }
    }
}

/// Service registry for local services
#[derive(Debug)]
pub struct ServiceRegistry {
    /// Registered services
    services: HashMap<ServiceId, ServiceInfo>,
    /// Service instances
    instances: HashMap<ServiceId, Vec<ServiceInstance>>,
    /// Service watchers
    watchers: HashMap<ServiceId, Vec<ServiceWatcher>>,
}

/// Remote services cache
#[derive(Debug)]
pub struct RemoteServiceCache {
    /// Cached services by node
    services_by_node: HashMap<String, HashMap<ServiceId, ServiceInfo>>,
    /// Service resolution cache
    resolution_cache: HashMap<ServiceQuery, ServiceResolution>,
    /// Cache expiry times
    cache_expiry: HashMap<ServiceQuery, Instant>,
}

/// Peer manager for network topology
#[derive(Debug)]
pub struct PeerManager {
    /// Known peers
    peers: HashMap<String, PeerInfo>,
    /// Peer connections
    connections: HashMap<String, PeerConnection>,
    /// Network topology
    topology: NetworkTopology,
    /// Peer groups (for container namespaces, regions, etc.)
    peer_groups: HashMap<String, PeerGroup>,
}

/// Service identifier
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceId {
    /// Service name
    pub name: String,
    /// Service namespace (optional)
    pub namespace: Option<String>,
    /// Service version (optional)
    pub version: Option<String>,
}

impl std::fmt::Display for ServiceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (&self.namespace, &self.version) {
            (Some(ns), Some(v)) => write!(f, "{}.{}.{}", ns, self.name, v),
            (Some(ns), None) => write!(f, "{}.{}", ns, self.name),
            (None, Some(v)) => write!(f, "{}.{}", self.name, v),
            (None, None) => write!(f, "{}", self.name),
        }
    }
}

/// Service information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    /// Service ID
    pub id: ServiceId,
    /// Service type
    pub service_type: ServiceType,
    /// Service description
    pub description: String,
    /// Service metadata
    pub metadata: HashMap<String, String>,
    /// Service tags
    pub tags: HashSet<String>,
    /// Service endpoints
    pub endpoints: Vec<ServiceEndpoint>,
    /// Service health check
    pub health_check: Option<HealthCheck>,
    /// Service registration time
    pub registered_at: SystemTime,
    /// Service TTL
    pub ttl: Duration,
}

/// Service types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServiceType {
    /// HTTP service
    Http,
    /// HTTPS service
    Https,
    /// QUIC service
    Quic,
    /// gRPC service
    Grpc,
    /// Database service
    Database,
    /// Message queue
    MessageQueue,
    /// Container service (BOLT)
    Container,
    /// Custom service type
    Custom(String),
}

/// Service endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    /// Endpoint address
    pub address: SocketAddr,
    /// Endpoint protocol
    pub protocol: EndpointProtocol,
    /// Endpoint weight for load balancing
    pub weight: u32,
    /// Endpoint health status
    pub health: EndpointHealth,
    /// Endpoint metadata
    pub metadata: HashMap<String, String>,
}

/// Endpoint protocols
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EndpointProtocol {
    Tcp,
    Udp,
    Quic,
    Http,
    Https,
    Grpc,
    Custom(String),
}

/// Endpoint health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EndpointHealth {
    Healthy,
    Unhealthy,
    Unknown,
    Degraded,
}

/// Health check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    /// Health check type
    pub check_type: HealthCheckType,
    /// Check interval
    pub interval: Duration,
    /// Check timeout
    pub timeout: Duration,
    /// Unhealthy threshold
    pub unhealthy_threshold: u32,
    /// Healthy threshold
    pub healthy_threshold: u32,
}

/// Health check types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HealthCheckType {
    /// TCP connection check
    Tcp,
    /// HTTP GET request
    Http { path: String, expected_status: u16 },
    /// QUIC connection check
    Quic,
    /// Custom check script
    Script { command: String },
}

/// Service instance
#[derive(Debug, Clone)]
pub struct ServiceInstance {
    /// Instance ID
    pub id: String,
    /// Service info
    pub service: ServiceInfo,
    /// Hosting node
    pub node_id: String,
    /// Instance health
    pub health: InstanceHealth,
    /// Last health check
    pub last_health_check: Instant,
}

/// Instance health information
#[derive(Debug, Clone)]
pub struct InstanceHealth {
    /// Health status
    pub status: EndpointHealth,
    /// Health score (0-100)
    pub score: u8,
    /// Last successful check
    pub last_success: Option<Instant>,
    /// Consecutive failures
    pub consecutive_failures: u32,
}

/// Service watcher for notifications
#[derive(Debug)]
pub struct ServiceWatcher {
    /// Watcher ID
    pub id: String,
    /// Service query
    pub query: ServiceQuery,
    /// Event sender
    pub sender: mpsc::UnboundedSender<ServiceEvent>,
}

/// Service query for discovery
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceQuery {
    /// Service name pattern
    pub name_pattern: String,
    /// Namespace filter
    pub namespace: Option<String>,
    /// Required tags
    pub required_tags: HashSet<String>,
    /// Metadata filters
    pub metadata_filters: HashMap<String, String>,
    /// Health requirement
    pub require_healthy: bool,
}

impl std::hash::Hash for ServiceQuery {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.name_pattern.hash(state);
        self.namespace.hash(state);
        // Convert HashSet to sorted Vec for consistent hashing
        let mut tags: Vec<_> = self.required_tags.iter().collect();
        tags.sort();
        tags.hash(state);
        // Convert HashMap to sorted Vec for consistent hashing
        let mut metadata: Vec<_> = self.metadata_filters.iter().collect();
        metadata.sort();
        metadata.hash(state);
        self.require_healthy.hash(state);
    }
}

/// Service resolution result
#[derive(Debug, Clone)]
pub struct ServiceResolution {
    /// Resolved services
    pub services: Vec<ServiceInstance>,
    /// Resolution timestamp
    pub resolved_at: Instant,
    /// Resolution source
    pub source: ResolutionSource,
}

/// Resolution sources
#[derive(Debug, Clone)]
pub enum ResolutionSource {
    Local,
    Cache,
    Remote(String),
    Discovery(ProtocolType),
}

/// Peer information
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Peer ID
    pub id: String,
    /// Peer addresses
    pub addresses: Vec<SocketAddr>,
    /// Peer capabilities
    pub capabilities: PeerCapabilities,
    /// Peer metadata
    pub metadata: HashMap<String, String>,
    /// Last seen time
    pub last_seen: Instant,
    /// Peer state
    pub state: PeerState,
}

/// Peer capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerCapabilities {
    /// Supports QUIC
    pub supports_quic: bool,
    /// Supports mesh networking
    pub supports_mesh: bool,
    /// Supports service discovery
    pub supports_discovery: bool,
    /// Supports container networking
    pub supports_containers: bool,
    /// Maximum message size
    pub max_message_size: usize,
    /// Supported protocols
    pub protocols: Vec<String>,
}

/// Peer states
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerState {
    Discovered,
    Connecting,
    Connected,
    Disconnected,
    Failed,
}

/// Peer connection information
#[derive(Debug)]
pub struct PeerConnection {
    /// Connection ID
    pub connection_id: ConnectionId,
    /// Connection instance
    pub connection: Arc<Connection>,
    /// Connection state
    pub state: ConnectionState,
    /// Connection metrics
    pub metrics: ConnectionMetrics,
}

/// Connection states
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    Establishing,
    Active,
    Idle,
    Closing,
    Closed,
}

/// Connection metrics
#[derive(Debug, Clone)]
pub struct ConnectionMetrics {
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Messages sent
    pub messages_sent: u64,
    /// Messages received
    pub messages_received: u64,
    /// Round-trip time
    pub rtt: Duration,
    /// Connection uptime
    pub uptime: Duration,
}

/// Network topology representation
#[derive(Debug)]
pub struct NetworkTopology {
    /// Topology graph (adjacency list)
    pub graph: HashMap<String, HashSet<String>>,
    /// Node distances (shortest paths)
    pub distances: HashMap<(String, String), u32>,
    /// Network clusters
    pub clusters: Vec<NetworkCluster>,
}

/// Network cluster
#[derive(Debug, Clone)]
pub struct NetworkCluster {
    /// Cluster ID
    pub id: String,
    /// Cluster members
    pub members: HashSet<String>,
    /// Cluster metadata
    pub metadata: HashMap<String, String>,
}

/// Peer group for organizing peers
#[derive(Debug, Clone)]
pub struct PeerGroup {
    /// Group ID
    pub id: String,
    /// Group type
    pub group_type: PeerGroupType,
    /// Group members
    pub members: HashSet<String>,
    /// Group policies
    pub policies: Vec<GroupPolicy>,
}

/// Peer group types
#[derive(Debug, Clone)]
pub enum PeerGroupType {
    /// Container namespace
    Namespace(String),
    /// Geographic region
    Region(String),
    /// Service tier
    Tier(String),
    /// Custom group
    Custom(String),
}

/// Group policy
#[derive(Debug, Clone)]
pub struct GroupPolicy {
    /// Policy name
    pub name: String,
    /// Policy rules
    pub rules: Vec<PolicyRule>,
}

/// Policy rule
#[derive(Debug, Clone)]
pub struct PolicyRule {
    /// Rule condition
    pub condition: String,
    /// Rule action
    pub action: String,
}

/// Discovery protocol types
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProtocolType {
    MDns,
    DnsSd,
    Dht,
    Gossip,
    Kubernetes,
    Custom(String),
}

/// Discovery protocol trait
pub trait DiscoveryProtocol: Send + Sync + std::fmt::Debug {
    /// Initialize the protocol
    fn initialize(&self, config: &DiscoveryConfig) -> Result<()>;

    /// Announce a service
    fn announce_service(&self, service: &ServiceInfo) -> Result<()>;

    /// Discover services
    fn discover_services(&self, query: &ServiceQuery) -> Result<Vec<ServiceInstance>>;

    /// Remove service announcement
    fn remove_service(&self, service_id: &ServiceId) -> Result<()>;

    /// Get protocol capabilities
    fn capabilities(&self) -> ProtocolCapabilities;
}

/// Protocol capabilities
#[derive(Debug, Clone)]
pub struct ProtocolCapabilities {
    /// Supports service announcement
    pub supports_announcement: bool,
    /// Supports service discovery
    pub supports_discovery: bool,
    /// Supports peer discovery
    pub supports_peer_discovery: bool,
    /// Maximum message size
    pub max_message_size: usize,
}

/// Discovery events
#[derive(Debug, Clone)]
pub enum DiscoveryEvent {
    /// Service registered
    ServiceRegistered {
        service_id: ServiceId,
        node_id: String,
    },
    /// Service unregistered
    ServiceUnregistered {
        service_id: ServiceId,
        node_id: String,
    },
    /// Service discovered
    ServiceDiscovered {
        service: ServiceInstance,
        source: ResolutionSource,
    },
    /// Peer discovered
    PeerDiscovered {
        peer_id: String,
        peer_info: PeerInfo,
    },
    /// Peer connected
    PeerConnected {
        peer_id: String,
        connection_id: ConnectionId,
    },
    /// Peer disconnected
    PeerDisconnected {
        peer_id: String,
        reason: String,
    },
    /// Service health changed
    ServiceHealthChanged {
        service_id: ServiceId,
        old_health: EndpointHealth,
        new_health: EndpointHealth,
    },
}

/// Service events for watchers
#[derive(Debug, Clone)]
pub enum ServiceEvent {
    /// Service added
    Added(ServiceInstance),
    /// Service updated
    Updated(ServiceInstance),
    /// Service removed
    Removed(ServiceId),
    /// Health changed
    HealthChanged {
        service_id: ServiceId,
        health: EndpointHealth,
    },
}

/// Discovery statistics
#[derive(Debug, Default, Clone)]
pub struct DiscoveryStats {
    /// Total services registered
    pub services_registered: u64,
    /// Total services discovered
    pub services_discovered: u64,
    /// Total peers discovered
    pub peers_discovered: u64,
    /// Active service instances
    pub active_services: usize,
    /// Active peers
    pub active_peers: usize,
    /// Discovery queries performed
    pub discovery_queries: u64,
    /// Cache hits
    pub cache_hits: u64,
    /// Cache misses
    pub cache_misses: u64,
}

impl ServiceDiscoveryManager {
    /// Create a new service discovery manager
    pub async fn new(config: DiscoveryConfig) -> Result<Self> {
        info!("Creating service discovery manager for node {}", config.node_id);

        let (event_tx, _) = broadcast::channel(1000);

        let manager = Self {
            config,
            local_services: Arc::new(RwLock::new(ServiceRegistry {
                services: HashMap::new(),
                instances: HashMap::new(),
                watchers: HashMap::new(),
            })),
            remote_services: Arc::new(RwLock::new(RemoteServiceCache {
                services_by_node: HashMap::new(),
                resolution_cache: HashMap::new(),
                cache_expiry: HashMap::new(),
            })),
            peer_manager: Arc::new(RwLock::new(PeerManager {
                peers: HashMap::new(),
                connections: HashMap::new(),
                topology: NetworkTopology {
                    graph: HashMap::new(),
                    distances: HashMap::new(),
                    clusters: Vec::new(),
                },
                peer_groups: HashMap::new(),
            })),
            discovery_protocols: Arc::new(RwLock::new(HashMap::new())),
            event_broadcaster: event_tx,
            task_handles: Vec::new(),
            stats: Arc::new(RwLock::new(DiscoveryStats::default())),
        };

        Ok(manager)
    }

    /// Start the service discovery manager
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting service discovery manager");

        // Initialize discovery protocols
        self.initialize_protocols().await?;

        // Start background tasks
        let announcement_task = self.start_announcement_task().await;
        self.task_handles.push(announcement_task);

        let discovery_task = self.start_discovery_task().await;
        self.task_handles.push(discovery_task);

        let health_check_task = self.start_health_check_task().await;
        self.task_handles.push(health_check_task);

        let cleanup_task = self.start_cleanup_task().await;
        self.task_handles.push(cleanup_task);

        let stats_task = self.start_stats_task().await;
        self.task_handles.push(stats_task);

        info!("Service discovery manager started successfully");
        Ok(())
    }

    /// Initialize discovery protocols
    async fn initialize_protocols(&self) -> Result<()> {
        let mut protocols = self.discovery_protocols.write().await;

        // Add enabled protocols
        if self.config.enable_mdns {
            protocols.insert(ProtocolType::MDns, Box::new(MDnsProtocol::new()));
        }

        if self.config.enable_dns_sd {
            protocols.insert(ProtocolType::DnsSd, Box::new(DnsSdProtocol::new()));
        }

        if self.config.enable_gossip {
            protocols.insert(ProtocolType::Gossip, Box::new(GossipProtocol::new()));
        }

        if self.config.kubernetes_integration {
            protocols.insert(ProtocolType::Kubernetes, Box::new(KubernetesProtocol::new()));
        }

        // Initialize all protocols
        for protocol in protocols.values() {
            protocol.initialize(&self.config)?;
        }

        info!("Initialized {} discovery protocols", protocols.len());
        Ok(())
    }

    /// Register a local service
    pub async fn register_service(&self, service: ServiceInfo) -> Result<()> {
        info!("Registering service: {}", service.id);

        // Add to local registry
        {
            let mut registry = self.local_services.write().await;
            registry.services.insert(service.id.clone(), service.clone());

            // Create service instance
            let instance = ServiceInstance {
                id: uuid::Uuid::new_v4().to_string(),
                service: service.clone(),
                node_id: self.config.node_id.clone(),
                health: InstanceHealth {
                    status: EndpointHealth::Unknown,
                    score: 100,
                    last_success: None,
                    consecutive_failures: 0,
                },
                last_health_check: Instant::now(),
            };

            registry.instances.entry(service.id.clone())
                .or_insert_with(Vec::new)
                .push(instance);
        }

        // Announce through discovery protocols
        {
            let protocols = self.discovery_protocols.read().await;
            for protocol in protocols.values() {
                if let Err(e) = protocol.announce_service(&service) {
                    warn!("Failed to announce service through protocol: {}", e);
                }
            }
        }

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.services_registered += 1;
        }

        // Emit event
        let _ = self.event_broadcaster.send(DiscoveryEvent::ServiceRegistered {
            service_id: service.id,
            node_id: self.config.node_id.clone(),
        });

        info!("Service registered successfully");
        Ok(())
    }

    /// Discover services matching a query
    pub async fn discover_services(&self, query: ServiceQuery) -> Result<Vec<ServiceInstance>> {
        debug!("Discovering services for query: {:?}", query);

        // Check cache first
        let cached_result = {
            let cache = self.remote_services.read().await;
            cache.resolution_cache.get(&query).cloned()
        };

        if let Some(cached) = cached_result {
            // Check if cache is still valid
            if cached.resolved_at.elapsed() < Duration::from_secs(60) {
                let mut stats = self.stats.write().await;
                stats.cache_hits += 1;
                return Ok(cached.services);
            }
        }

        // Cache miss - perform discovery
        let mut all_services = Vec::new();

        // Search local services
        {
            let registry = self.local_services.read().await;
            for instances in registry.instances.values() {
                for instance in instances {
                    if self.matches_query(&instance.service, &query) {
                        all_services.push(instance.clone());
                    }
                }
            }
        }

        // Search through discovery protocols
        {
            let protocols = self.discovery_protocols.read().await;
            for protocol in protocols.values() {
                match protocol.discover_services(&query) {
                    Ok(services) => all_services.extend(services),
                    Err(e) => debug!("Discovery protocol failed: {}", e),
                }
            }
        }

        // Update cache
        {
            let mut cache = self.remote_services.write().await;
            let resolution = ServiceResolution {
                services: all_services.clone(),
                resolved_at: Instant::now(),
                source: ResolutionSource::Discovery(ProtocolType::Gossip), // Simplified
            };
            cache.resolution_cache.insert(query, resolution);
        }

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.services_discovered += all_services.len() as u64;
            stats.discovery_queries += 1;
            stats.cache_misses += 1;
        }

        debug!("Discovered {} services", all_services.len());
        Ok(all_services)
    }

    /// Check if service matches query
    fn matches_query(&self, service: &ServiceInfo, query: &ServiceQuery) -> bool {
        // Check name pattern
        if !service.id.name.contains(&query.name_pattern) {
            return false;
        }

        // Check namespace
        if let Some(ns) = &query.namespace {
            if service.id.namespace.as_ref() != Some(ns) {
                return false;
            }
        }

        // Check required tags
        for tag in &query.required_tags {
            if !service.tags.contains(tag) {
                return false;
            }
        }

        // Check metadata filters
        for (key, value) in &query.metadata_filters {
            if service.metadata.get(key) != Some(value) {
                return false;
            }
        }

        true
    }

    /// Add a peer to the network
    pub async fn add_peer(&self, peer_info: PeerInfo) -> Result<()> {
        info!("Adding peer: {}", peer_info.id);

        {
            let mut manager = self.peer_manager.write().await;
            manager.peers.insert(peer_info.id.clone(), peer_info.clone());

            // Update topology
            manager.topology.graph.entry(self.config.node_id.clone())
                .or_insert_with(HashSet::new)
                .insert(peer_info.id.clone());
        }

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.peers_discovered += 1;
        }

        // Emit event
        let _ = self.event_broadcaster.send(DiscoveryEvent::PeerDiscovered {
            peer_id: peer_info.id.clone(),
            peer_info,
        });

        info!("Peer added successfully");
        Ok(())
    }

    /// Start service announcement task
    async fn start_announcement_task(&self) -> JoinHandle<()> {
        let local_services = Arc::clone(&self.local_services);
        let discovery_protocols = Arc::clone(&self.discovery_protocols);
        let interval_duration = self.config.announcement_interval;

        tokio::spawn(async move {
            let mut interval = interval(interval_duration);

            loop {
                interval.tick().await;

                debug!("Performing service announcements");

                // Get services to announce
                let services = {
                    let registry = local_services.read().await;
                    registry.services.values().cloned().collect::<Vec<_>>()
                };

                // Announce through all protocols
                {
                    let protocols = discovery_protocols.read().await;
                    for service in &services {
                        for protocol in protocols.values() {
                            if let Err(e) = protocol.announce_service(service) {
                                trace!("Failed to announce service {}: {}", service.id, e);
                            }
                        }
                    }
                }

                debug!("Announced {} services", services.len());
            }
        })
    }

    /// Start continuous discovery task
    async fn start_discovery_task(&self) -> JoinHandle<()> {
        let peer_manager = Arc::clone(&self.peer_manager);
        let discovery_protocols = Arc::clone(&self.discovery_protocols);

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(60));

            loop {
                interval.tick().await;

                debug!("Performing peer discovery");

                // Discover peers through protocols
                // This would implement peer discovery logic
                // For now, we'll just log the activity

                let peer_count = peer_manager.read().await.peers.len();
                debug!("Current peer count: {}", peer_count);
            }
        })
    }

    /// Start health check task
    async fn start_health_check_task(&self) -> JoinHandle<()> {
        let local_services = Arc::clone(&self.local_services);

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(30));

            loop {
                interval.tick().await;

                debug!("Performing health checks");

                // Perform health checks on service instances
                {
                    let mut registry = local_services.write().await;
                    for instances in registry.instances.values_mut() {
                        for instance in instances {
                            // Simplified health check
                            instance.last_health_check = Instant::now();
                            instance.health.status = EndpointHealth::Healthy;
                        }
                    }
                }
            }
        })
    }

    /// Start cleanup task
    async fn start_cleanup_task(&self) -> JoinHandle<()> {
        let remote_services = Arc::clone(&self.remote_services);
        let peer_manager = Arc::clone(&self.peer_manager);

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(300)); // 5 minutes

            loop {
                interval.tick().await;

                debug!("Performing cleanup");

                let now = Instant::now();

                // Clean expired cache entries
                {
                    let mut cache = remote_services.write().await;
                    // Collect expired queries first
                    let expired_queries: Vec<_> = cache.cache_expiry.iter()
                        .filter_map(|(query, expiry)| {
                            if now > *expiry {
                                Some(query.clone())
                            } else {
                                None
                            }
                        })
                        .collect();

                    // Remove expired entries
                    for query in &expired_queries {
                        cache.cache_expiry.remove(query);
                        cache.resolution_cache.remove(query);
                    }
                }

                // Clean inactive peers
                {
                    let mut manager = peer_manager.write().await;
                    manager.peers.retain(|peer_id, peer| {
                        let inactive_duration = now.duration_since(peer.last_seen);
                        if inactive_duration > Duration::from_secs(600) { // 10 minutes
                            debug!("Removing inactive peer: {}", peer_id);
                            false
                        } else {
                            true
                        }
                    });
                }
            }
        })
    }

    /// Start statistics collection task
    async fn start_stats_task(&self) -> JoinHandle<()> {
        let local_services = Arc::clone(&self.local_services);
        let peer_manager = Arc::clone(&self.peer_manager);
        let stats = Arc::clone(&self.stats);

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(10));

            loop {
                interval.tick().await;

                // Update statistics
                let mut stats_guard = stats.write().await;

                // Count active services
                let service_count = local_services.read().await.services.len();
                stats_guard.active_services = service_count;

                // Count active peers
                let peer_count = peer_manager.read().await.peers.len();
                stats_guard.active_peers = peer_count;

                trace!("Discovery stats: {} services, {} peers", service_count, peer_count);
            }
        })
    }

    /// Get discovery statistics
    pub async fn stats(&self) -> DiscoveryStats {
        self.stats.read().await.clone()
    }

    /// Shutdown the service discovery manager
    pub async fn shutdown(&mut self) {
        info!("Shutting down service discovery manager");

        // Cancel all background tasks
        for handle in self.task_handles.drain(..) {
            handle.abort();
        }

        // Unregister all services
        let service_ids: Vec<_> = {
            let registry = self.local_services.read().await;
            registry.services.keys().cloned().collect()
        };

        for service_id in service_ids {
            if let Err(e) = self.unregister_service(&service_id).await {
                warn!("Error unregistering service {} during shutdown: {}", service_id, e);
            }
        }

        info!("Service discovery manager shutdown complete");
    }

    /// Unregister a service
    pub async fn unregister_service(&self, service_id: &ServiceId) -> Result<()> {
        info!("Unregistering service: {}", service_id);

        // Remove from local registry
        {
            let mut registry = self.local_services.write().await;
            registry.services.remove(service_id);
            registry.instances.remove(service_id);
        }

        // Remove from discovery protocols
        {
            let protocols = self.discovery_protocols.read().await;
            for protocol in protocols.values() {
                if let Err(e) = protocol.remove_service(service_id) {
                    warn!("Failed to remove service from protocol: {}", e);
                }
            }
        }

        // Emit event
        let _ = self.event_broadcaster.send(DiscoveryEvent::ServiceUnregistered {
            service_id: service_id.clone(),
            node_id: self.config.node_id.clone(),
        });

        info!("Service unregistered successfully");
        Ok(())
    }
}

/// mDNS discovery protocol implementation
#[derive(Debug)]
pub struct MDnsProtocol;

impl MDnsProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl DiscoveryProtocol for MDnsProtocol {
    fn initialize(&self, _config: &DiscoveryConfig) -> Result<()> {
        debug!("Initializing mDNS protocol");
        Ok(())
    }

    fn announce_service(&self, service: &ServiceInfo) -> Result<()> {
        debug!("Announcing service via mDNS: {}", service.id);
        // Real implementation would use mDNS library
        Ok(())
    }

    fn discover_services(&self, query: &ServiceQuery) -> Result<Vec<ServiceInstance>> {
        debug!("Discovering services via mDNS: {:?}", query);
        // Real implementation would query mDNS
        Ok(Vec::new())
    }

    fn remove_service(&self, service_id: &ServiceId) -> Result<()> {
        debug!("Removing service from mDNS: {}", service_id);
        Ok(())
    }

    fn capabilities(&self) -> ProtocolCapabilities {
        ProtocolCapabilities {
            supports_announcement: true,
            supports_discovery: true,
            supports_peer_discovery: true,
            max_message_size: 1024,
        }
    }
}

/// DNS-SD discovery protocol implementation
#[derive(Debug)]
pub struct DnsSdProtocol;

impl DnsSdProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl DiscoveryProtocol for DnsSdProtocol {
    fn initialize(&self, _config: &DiscoveryConfig) -> Result<()> {
        debug!("Initializing DNS-SD protocol");
        Ok(())
    }

    fn announce_service(&self, service: &ServiceInfo) -> Result<()> {
        debug!("Announcing service via DNS-SD: {}", service.id);
        Ok(())
    }

    fn discover_services(&self, query: &ServiceQuery) -> Result<Vec<ServiceInstance>> {
        debug!("Discovering services via DNS-SD: {:?}", query);
        Ok(Vec::new())
    }

    fn remove_service(&self, service_id: &ServiceId) -> Result<()> {
        debug!("Removing service from DNS-SD: {}", service_id);
        Ok(())
    }

    fn capabilities(&self) -> ProtocolCapabilities {
        ProtocolCapabilities {
            supports_announcement: true,
            supports_discovery: true,
            supports_peer_discovery: false,
            max_message_size: 2048,
        }
    }
}

/// Gossip discovery protocol implementation
#[derive(Debug)]
pub struct GossipProtocol;

impl GossipProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl DiscoveryProtocol for GossipProtocol {
    fn initialize(&self, _config: &DiscoveryConfig) -> Result<()> {
        debug!("Initializing Gossip protocol");
        Ok(())
    }

    fn announce_service(&self, service: &ServiceInfo) -> Result<()> {
        debug!("Announcing service via Gossip: {}", service.id);
        Ok(())
    }

    fn discover_services(&self, query: &ServiceQuery) -> Result<Vec<ServiceInstance>> {
        debug!("Discovering services via Gossip: {:?}", query);
        Ok(Vec::new())
    }

    fn remove_service(&self, service_id: &ServiceId) -> Result<()> {
        debug!("Removing service from Gossip: {}", service_id);
        Ok(())
    }

    fn capabilities(&self) -> ProtocolCapabilities {
        ProtocolCapabilities {
            supports_announcement: true,
            supports_discovery: true,
            supports_peer_discovery: true,
            max_message_size: 4096,
        }
    }
}

/// Kubernetes discovery protocol implementation
#[derive(Debug)]
pub struct KubernetesProtocol;

impl KubernetesProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl DiscoveryProtocol for KubernetesProtocol {
    fn initialize(&self, _config: &DiscoveryConfig) -> Result<()> {
        debug!("Initializing Kubernetes protocol");
        Ok(())
    }

    fn announce_service(&self, service: &ServiceInfo) -> Result<()> {
        debug!("Announcing service via Kubernetes: {}", service.id);
        // Would create/update Kubernetes Service resource
        Ok(())
    }

    fn discover_services(&self, query: &ServiceQuery) -> Result<Vec<ServiceInstance>> {
        debug!("Discovering services via Kubernetes: {:?}", query);
        // Would query Kubernetes API for services
        Ok(Vec::new())
    }

    fn remove_service(&self, service_id: &ServiceId) -> Result<()> {
        debug!("Removing service from Kubernetes: {}", service_id);
        Ok(())
    }

    fn capabilities(&self) -> ProtocolCapabilities {
        ProtocolCapabilities {
            supports_announcement: true,
            supports_discovery: true,
            supports_peer_discovery: false,
            max_message_size: 1024 * 1024, // 1MB
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_service_discovery_manager_creation() {
        let config = DiscoveryConfig::default();
        let manager = ServiceDiscoveryManager::new(config).await;
        assert!(manager.is_ok());
    }

    #[tokio::test]
    async fn test_service_registration() {
        let config = DiscoveryConfig::default();
        let manager = ServiceDiscoveryManager::new(config).await.unwrap();

        let service = ServiceInfo {
            id: ServiceId {
                name: "test-service".to_string(),
                namespace: Some("default".to_string()),
                version: Some("1.0.0".to_string()),
            },
            service_type: ServiceType::Http,
            description: "Test service".to_string(),
            metadata: HashMap::new(),
            tags: HashSet::new(),
            endpoints: vec![ServiceEndpoint {
                address: "127.0.0.1:8080".parse().unwrap(),
                protocol: EndpointProtocol::Http,
                weight: 100,
                health: EndpointHealth::Healthy,
                metadata: HashMap::new(),
            }],
            health_check: None,
            registered_at: SystemTime::now(),
            ttl: Duration::from_secs(300),
        };

        let result = manager.register_service(service).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_service_id_display() {
        let service_id = ServiceId {
            name: "test".to_string(),
            namespace: Some("ns".to_string()),
            version: Some("1.0".to_string()),
        };

        assert_eq!(service_id.to_string(), "ns.test.1.0");
    }

    #[test]
    fn test_protocol_capabilities() {
        let mdns = MDnsProtocol::new();
        let caps = mdns.capabilities();
        assert!(caps.supports_announcement);
        assert!(caps.supports_discovery);
    }
}