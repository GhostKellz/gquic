//! DERP (Designated Encrypted Relay Protocol) Implementation
//!
//! This module provides a DERP relay system for NAT traversal in GQUIC,
//! enabling peer-to-peer connections through encrypted relay servers
//! when direct connections are not possible.

use crate::quic::{
    connection::{Connection, ConnectionId},
    error::{QuicError, Result, ProtocolError},
};
use crate::wireguard::{WireGuardManager, WireGuardConfig};
use crate::network::{NetworkInterface, NetworkEvent};
use bytes::{Bytes, BytesMut, BufMut, Buf};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{RwLock, Mutex, mpsc, broadcast};
use tokio::task::JoinHandle;
use tokio::time::{timeout, sleep, interval};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info, warn, error, trace};
use serde::{Serialize, Deserialize};

/// DERP relay server for NAT traversal
#[derive(Debug)]
pub struct DerpServer {
    /// Server configuration
    config: DerpServerConfig,
    /// Connected clients
    clients: Arc<RwLock<HashMap<DerpNodeId, DerpConnectedClient>>>,
    /// Active relay sessions
    relay_sessions: Arc<RwLock<HashMap<RelaySessionId, RelaySession>>>,
    /// Message queue for relay forwarding
    message_queue: Arc<Mutex<VecDeque<DerpMessage>>>,
    /// Server statistics
    stats: Arc<RwLock<DerpStats>>,
    /// Background task handles
    task_handles: Vec<JoinHandle<()>>,
    /// Event broadcaster
    event_broadcaster: broadcast::Sender<DerpEvent>,
}

/// DERP client for connecting to relay servers
pub struct DerpClient {
    /// Client configuration
    config: DerpClientConfig,
    /// Connected relay servers
    relays: Arc<RwLock<HashMap<String, DerpRelay>>>,
    /// Peer discovery manager
    peer_discovery: Arc<RwLock<PeerDiscoveryManager>>,
    /// NAT traversal coordinator
    nat_traversal: Arc<Mutex<NatTraversalCoordinator>>,
    /// Local node information
    local_node: DerpNodeInfo,
    /// Message handlers
    message_handlers: Arc<RwLock<HashMap<DerpMessageType, Box<dyn DerpMessageHandler>>>>,
    /// Background task handles
    task_handles: Vec<JoinHandle<()>>,
}

/// DERP server configuration
#[derive(Debug, Clone)]
pub struct DerpServerConfig {
    /// Server listen address
    pub listen_addr: SocketAddr,
    /// Server region name
    pub region: String,
    /// Maximum concurrent clients
    pub max_clients: usize,
    /// Client connection timeout
    pub client_timeout: Duration,
    /// Relay message TTL
    pub message_ttl: Duration,
    /// Enable message persistence
    pub enable_persistence: bool,
    /// Maximum message size
    pub max_message_size: usize,
    /// Rate limiting configuration
    pub rate_limits: RateLimitConfig,
    /// TLS configuration for secure relaying
    pub tls_config: Option<TlsConfig>,
}

/// DERP client configuration
#[derive(Debug, Clone)]
pub struct DerpClientConfig {
    /// Preferred relay servers
    pub preferred_relays: Vec<String>,
    /// Home relay region
    pub home_region: String,
    /// Connection retry attempts
    pub retry_attempts: u32,
    /// Connection timeout
    pub connection_timeout: Duration,
    /// Keep-alive interval
    pub keepalive_interval: Duration,
    /// Enable mesh mode for direct connections
    pub enable_mesh_mode: bool,
    /// NAT traversal timeout
    pub nat_traversal_timeout: Duration,
}

/// Rate limiting configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Messages per second per client
    pub messages_per_second: u32,
    /// Bytes per second per client
    pub bytes_per_second: u64,
    /// Burst allowance
    pub burst_allowance: u32,
}

/// TLS configuration for DERP
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Certificate path
    pub cert_path: String,
    /// Private key path
    pub key_path: String,
    /// Client certificate verification
    pub verify_client_certs: bool,
}

/// DERP node identifier
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerpNodeId(pub String);

impl std::fmt::Display for DerpNodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// DERP node information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerpNodeInfo {
    /// Node ID
    pub id: DerpNodeId,
    /// Node public key
    pub public_key: String,
    /// Node endpoints (addresses where node can be reached)
    pub endpoints: Vec<SocketAddr>,
    /// Node capabilities
    pub capabilities: NodeCapabilities,
    /// Last seen timestamp
    pub last_seen: SystemTime,
    /// Node metadata
    pub metadata: HashMap<String, String>,
}

/// Node capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCapabilities {
    /// Supports direct connections
    pub supports_direct: bool,
    /// Supports mesh networking
    pub supports_mesh: bool,
    /// Supports container networking
    pub supports_containers: bool,
    /// Maximum message size
    pub max_message_size: usize,
}

/// DERP relay session identifier
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct RelaySessionId(pub String);

/// DERP relay session
#[derive(Debug)]
pub struct RelaySession {
    /// Session ID
    pub id: RelaySessionId,
    /// Source node
    pub source: DerpNodeId,
    /// Destination node
    pub destination: DerpNodeId,
    /// Session creation time
    pub created_at: Instant,
    /// Last activity time
    pub last_activity: Instant,
    /// Messages relayed
    pub messages_relayed: u64,
    /// Bytes relayed
    pub bytes_relayed: u64,
}

/// DERP message types
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DerpMessageType {
    /// Peer discovery message
    PeerDiscovery,
    /// NAT traversal coordination
    NatTraversal,
    /// Connection establishment
    Connection,
    /// Data relay
    DataRelay,
    /// Keep-alive message
    KeepAlive,
    /// Error notification
    Error,
    /// Custom application message
    Custom(String),
}

/// DERP message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerpMessage {
    /// Message ID
    pub id: String,
    /// Message type
    pub message_type: DerpMessageType,
    /// Source node
    pub source: DerpNodeId,
    /// Destination node
    pub destination: DerpNodeId,
    /// Message payload
    pub payload: Vec<u8>,
    /// Message timestamp
    pub timestamp: SystemTime,
    /// Message TTL
    pub ttl: Duration,
    /// Message priority
    pub priority: MessagePriority,
}

/// Message priority levels
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MessagePriority {
    Low,
    Normal,
    High,
    Critical,
}

/// DERP events
#[derive(Debug, Clone)]
pub enum DerpEvent {
    /// Client connected to relay
    ClientConnected {
        node_id: DerpNodeId,
        relay_addr: SocketAddr,
    },
    /// Client disconnected from relay
    ClientDisconnected {
        node_id: DerpNodeId,
        reason: String,
    },
    /// Peer discovered
    PeerDiscovered {
        peer_id: DerpNodeId,
        peer_info: DerpNodeInfo,
    },
    /// Direct connection established
    DirectConnectionEstablished {
        peer_id: DerpNodeId,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    },
    /// NAT traversal successful
    NatTraversalSuccess {
        peer_id: DerpNodeId,
        method: NatTraversalMethod,
    },
    /// Message relayed
    MessageRelayed {
        session_id: RelaySessionId,
        message_size: usize,
    },
}

/// NAT traversal methods
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NatTraversalMethod {
    /// Direct connection (no NAT)
    Direct,
    /// UPnP port mapping
    Upnp,
    /// STUN hole punching
    Stun,
    /// Relay through DERP server
    Relay,
}

/// Connected client information
#[derive(Debug, Clone)]
pub struct DerpConnectedClient {
    /// Node information
    pub node_info: DerpNodeInfo,
    /// Connection stream
    pub stream: Arc<Mutex<TcpStream>>,
    /// Last activity time
    pub last_activity: Instant,
    /// Rate limiter
    pub rate_limiter: RateLimiter,
}

/// Simple rate limiter
#[derive(Debug, Clone)]
pub struct RateLimiter {
    /// Messages in current window
    pub messages_in_window: u32,
    /// Bytes in current window
    pub bytes_in_window: u64,
    /// Window start time
    pub window_start: Instant,
    /// Configuration
    pub config: RateLimitConfig,
}

/// DERP relay connection
#[derive(Debug, Clone)]
pub struct DerpRelay {
    /// Relay server address
    pub server_addr: SocketAddr,
    /// Connection stream
    pub stream: Arc<Mutex<TcpStream>>,
    /// Connection state
    pub state: RelayConnectionState,
    /// Last ping time
    pub last_ping: Instant,
    /// Round-trip time
    pub rtt: Duration,
}

/// Relay connection states
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayConnectionState {
    Connecting,
    Connected,
    Reconnecting,
    Disconnected,
    Failed(String),
}

/// Peer discovery manager
#[derive(Debug)]
pub struct PeerDiscoveryManager {
    /// Known peers
    pub known_peers: HashMap<DerpNodeId, DerpNodeInfo>,
    /// Discovery announcements
    pub announcements: VecDeque<PeerAnnouncement>,
    /// Discovery queries
    pub queries: VecDeque<PeerQuery>,
}

/// Peer announcement
#[derive(Debug, Clone)]
pub struct PeerAnnouncement {
    /// Announcing node
    pub node_info: DerpNodeInfo,
    /// Announcement timestamp
    pub timestamp: Instant,
    /// Announcement TTL
    pub ttl: Duration,
}

/// Peer discovery query
#[derive(Debug, Clone)]
pub struct PeerQuery {
    /// Query ID
    pub id: String,
    /// Querying node
    pub querying_node: DerpNodeId,
    /// Query criteria
    pub criteria: PeerQueryCriteria,
    /// Query timestamp
    pub timestamp: Instant,
}

/// Peer query criteria
#[derive(Debug, Clone)]
pub struct PeerQueryCriteria {
    /// Node ID pattern
    pub node_id_pattern: Option<String>,
    /// Required capabilities
    pub required_capabilities: Option<NodeCapabilities>,
    /// Region preference
    pub region_preference: Option<String>,
}

/// NAT traversal coordinator
#[derive(Debug)]
pub struct NatTraversalCoordinator {
    /// Active traversal attempts
    pub active_attempts: HashMap<DerpNodeId, TraversalAttempt>,
    /// STUN servers
    pub stun_servers: Vec<SocketAddr>,
    /// UPnP client
    pub upnp_client: Option<UpnpClient>,
}

/// NAT traversal attempt
#[derive(Debug)]
pub struct TraversalAttempt {
    /// Target peer
    pub peer_id: DerpNodeId,
    /// Attempted methods
    pub attempted_methods: Vec<NatTraversalMethod>,
    /// Current method being tried
    pub current_method: Option<NatTraversalMethod>,
    /// Attempt start time
    pub started_at: Instant,
    /// Attempt timeout
    pub timeout: Duration,
}

/// UPnP client placeholder
#[derive(Debug)]
pub struct UpnpClient {
    /// Gateway address
    pub gateway_addr: SocketAddr,
    /// Mapped ports
    pub mapped_ports: HashMap<u16, u16>,
}

/// Message handler trait
pub trait DerpMessageHandler: Send + Sync {
    /// Handle a DERP message
    fn handle_message(&self, message: &DerpMessage) -> Result<Option<DerpMessage>>;
}

/// DERP statistics
#[derive(Debug, Default, Clone)]
pub struct DerpStats {
    /// Connected clients (server-side)
    pub connected_clients: usize,
    /// Active relay sessions
    pub active_sessions: usize,
    /// Total messages relayed
    pub total_messages: u64,
    /// Total bytes relayed
    pub total_bytes: u64,
    /// Successful NAT traversals
    pub successful_traversals: u64,
    /// Failed NAT traversals
    pub failed_traversals: u64,
    /// Direct connections established
    pub direct_connections: u64,
    /// Average message latency
    pub avg_message_latency: Duration,
}

impl DerpServer {
    /// Create a new DERP server
    pub async fn new(config: DerpServerConfig) -> Result<Self> {
        info!("Creating DERP server on {}", config.listen_addr);

        let (event_tx, _) = broadcast::channel(1000);

        let server = Self {
            config,
            clients: Arc::new(RwLock::new(HashMap::new())),
            relay_sessions: Arc::new(RwLock::new(HashMap::new())),
            message_queue: Arc::new(Mutex::new(VecDeque::new())),
            stats: Arc::new(RwLock::new(DerpStats::default())),
            task_handles: Vec::new(),
            event_broadcaster: event_tx,
        };

        Ok(server)
    }

    /// Start the DERP server
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting DERP server on {}", self.config.listen_addr);

        // Start TCP listener
        let listener = TcpListener::bind(self.config.listen_addr).await
            .map_err(|e| QuicError::Io(e.to_string()))?;

        // Start client acceptance task
        let accept_task = self.start_client_acceptance_task(listener).await;
        self.task_handles.push(accept_task);

        // Start message processing task
        let message_task = self.start_message_processing_task().await;
        self.task_handles.push(message_task);

        // Start cleanup task
        let cleanup_task = self.start_cleanup_task().await;
        self.task_handles.push(cleanup_task);

        // Start statistics task
        let stats_task = self.start_stats_task().await;
        self.task_handles.push(stats_task);

        info!("DERP server started successfully");
        Ok(())
    }

    /// Start client acceptance task
    async fn start_client_acceptance_task(&self, listener: TcpListener) -> JoinHandle<()> {
        let clients = Arc::clone(&self.clients);
        let max_clients = self.config.max_clients;
        let event_broadcaster = self.event_broadcaster.clone();

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        debug!("New client connection from {}", addr);

                        // Check client limit
                        let client_count = clients.read().await.len();
                        if client_count >= max_clients {
                            warn!("Client limit reached, rejecting connection from {}", addr);
                            continue;
                        }

                        // Handle client connection
                        tokio::spawn(Self::handle_client_connection(
                            stream,
                            addr,
                            Arc::clone(&clients),
                            event_broadcaster.clone(),
                        ));
                    },
                    Err(e) => {
                        error!("Failed to accept client connection: {}", e);
                        sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        })
    }

    /// Handle individual client connection
    async fn handle_client_connection(
        mut stream: TcpStream,
        addr: SocketAddr,
        clients: Arc<RwLock<HashMap<DerpNodeId, DerpConnectedClient>>>,
        event_broadcaster: broadcast::Sender<DerpEvent>,
    ) {
        info!("Handling client connection from {}", addr);

        // Perform handshake and authentication
        let node_info = match Self::perform_client_handshake(&mut stream).await {
            Ok(info) => info,
            Err(e) => {
                warn!("Client handshake failed for {}: {}", addr, e);
                return;
            }
        };

        let node_id = node_info.id.clone();

        // Create client entry
        let client = DerpConnectedClient {
            node_info: node_info.clone(),
            stream: Arc::new(Mutex::new(stream)),
            last_activity: Instant::now(),
            rate_limiter: RateLimiter {
                messages_in_window: 0,
                bytes_in_window: 0,
                window_start: Instant::now(),
                config: RateLimitConfig {
                    messages_per_second: 100,
                    bytes_per_second: 1024 * 1024, // 1MB/s
                    burst_allowance: 10,
                },
            },
        };

        // Add client to registry
        {
            let mut clients_guard = clients.write().await;
            clients_guard.insert(node_id.clone(), client);
        }

        // Emit connection event
        let _ = event_broadcaster.send(DerpEvent::ClientConnected {
            node_id: node_id.clone(),
            relay_addr: addr,
        });

        info!("Client {} connected successfully", node_id);

        // Client connection cleanup will be handled by the cleanup task
    }

    /// Perform client handshake
    async fn perform_client_handshake(stream: &mut TcpStream) -> Result<DerpNodeInfo> {
        // Read handshake message
        let mut buffer = [0u8; 1024];
        let bytes_read = stream.read(&mut buffer).await
            .map_err(|e| QuicError::Io(e.to_string()))?;

        if bytes_read == 0 {
            return Err(QuicError::Protocol(ProtocolError::InvalidState(
                "Client disconnected during handshake".to_string()
            )));
        }

        // Parse handshake (simplified)
        let handshake_data = &buffer[..bytes_read];
        let node_info: DerpNodeInfo = serde_json::from_slice(handshake_data)
            .map_err(|e| QuicError::Protocol(ProtocolError::InvalidPacket(
                format!("Invalid handshake: {}", e)
            )))?;

        // Send handshake response
        let response = serde_json::to_vec(&"OK").unwrap();
        stream.write_all(&response).await
            .map_err(|e| QuicError::Io(e.to_string()))?;

        Ok(node_info)
    }

    /// Start message processing task
    async fn start_message_processing_task(&self) -> JoinHandle<()> {
        let message_queue = Arc::clone(&self.message_queue);
        let clients = Arc::clone(&self.clients);
        let relay_sessions = Arc::clone(&self.relay_sessions);
        let stats = Arc::clone(&self.stats);

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_millis(10));

            loop {
                interval.tick().await;

                // Process queued messages
                let messages_to_process = {
                    let mut queue = message_queue.lock().await;
                    let batch_size = 100.min(queue.len());
                    queue.drain(..batch_size).collect::<Vec<_>>()
                };

                for message in messages_to_process {
                    if let Err(e) = Self::process_message(
                        &message,
                        &clients,
                        &relay_sessions,
                        &stats,
                    ).await {
                        warn!("Failed to process message {}: {}", message.id, e);
                    }
                }
            }
        })
    }

    /// Process a single message
    async fn process_message(
        message: &DerpMessage,
        clients: &Arc<RwLock<HashMap<DerpNodeId, DerpConnectedClient>>>,
        relay_sessions: &Arc<RwLock<HashMap<RelaySessionId, RelaySession>>>,
        stats: &Arc<RwLock<DerpStats>>,
    ) -> Result<()> {
        trace!("Processing message {} from {} to {}",
               message.id, message.source, message.destination);

        // Find destination client
        let destination_client = {
            let clients_guard = clients.read().await;
            clients_guard.get(&message.destination).cloned()
        };

        if let Some(client) = destination_client {
            // Forward message to client
            let serialized = serde_json::to_vec(message)
                .map_err(|e| QuicError::Protocol(ProtocolError::InvalidPacket(
                    format!("Failed to serialize message: {}", e)
                )))?;

            {
                let mut stream = client.stream.lock().await;
                stream.write_all(&serialized).await
                    .map_err(|e| QuicError::Io(e.to_string()))?;
            }

            // Update statistics
            {
                let mut stats_guard = stats.write().await;
                stats_guard.total_messages += 1;
                stats_guard.total_bytes += serialized.len() as u64;
            }

            debug!("Message {} forwarded to {}", message.id, message.destination);
        } else {
            debug!("Destination client {} not found for message {}",
                   message.destination, message.id);
        }

        Ok(())
    }

    /// Start cleanup task
    async fn start_cleanup_task(&self) -> JoinHandle<()> {
        let clients = Arc::clone(&self.clients);
        let relay_sessions = Arc::clone(&self.relay_sessions);
        let client_timeout = self.config.client_timeout;

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(30));

            loop {
                interval.tick().await;

                let now = Instant::now();

                // Clean up inactive clients
                {
                    let mut clients_guard = clients.write().await;
                    clients_guard.retain(|node_id, client| {
                        let inactive_duration = now.duration_since(client.last_activity);
                        if inactive_duration > client_timeout {
                            info!("Removing inactive client: {}", node_id);
                            false
                        } else {
                            true
                        }
                    });
                }

                // Clean up old relay sessions
                {
                    let mut sessions_guard = relay_sessions.write().await;
                    sessions_guard.retain(|session_id, session| {
                        let inactive_duration = now.duration_since(session.last_activity);
                        if inactive_duration > Duration::from_secs(300) { // 5 minutes
                            debug!("Removing inactive relay session: {}", session_id.0);
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
        let clients = Arc::clone(&self.clients);
        let relay_sessions = Arc::clone(&self.relay_sessions);
        let stats = Arc::clone(&self.stats);

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(10));

            loop {
                interval.tick().await;

                // Update statistics
                let mut stats_guard = stats.write().await;

                // Count connected clients
                let client_count = clients.read().await.len();
                stats_guard.connected_clients = client_count;

                // Count active sessions
                let session_count = relay_sessions.read().await.len();
                stats_guard.active_sessions = session_count;

                trace!("DERP stats: {} clients, {} sessions", client_count, session_count);
            }
        })
    }

    /// Get server statistics
    pub async fn stats(&self) -> DerpStats {
        self.stats.read().await.clone()
    }

    /// Shutdown the DERP server
    pub async fn shutdown(&mut self) {
        info!("Shutting down DERP server");

        // Cancel all background tasks
        for handle in self.task_handles.drain(..) {
            handle.abort();
        }

        // Disconnect all clients
        let client_ids: Vec<_> = {
            let clients = self.clients.read().await;
            clients.keys().cloned().collect()
        };

        for client_id in client_ids {
            // Send disconnect notification to clients
            // In a real implementation, this would send proper disconnect messages
        }

        info!("DERP server shutdown complete");
    }
}

impl DerpClient {
    /// Create a new DERP client
    pub async fn new(
        config: DerpClientConfig,
        local_node: DerpNodeInfo,
    ) -> Result<Self> {
        info!("Creating DERP client for node {}", local_node.id);

        let client = Self {
            config,
            relays: Arc::new(RwLock::new(HashMap::new())),
            peer_discovery: Arc::new(RwLock::new(PeerDiscoveryManager {
                known_peers: HashMap::new(),
                announcements: VecDeque::new(),
                queries: VecDeque::new(),
            })),
            nat_traversal: Arc::new(Mutex::new(NatTraversalCoordinator {
                active_attempts: HashMap::new(),
                stun_servers: vec![
                    "stun.l.google.com:19302".parse().unwrap(),
                    "stun1.l.google.com:19302".parse().unwrap(),
                ],
                upnp_client: None,
            })),
            local_node,
            message_handlers: Arc::new(RwLock::new(HashMap::new())),
            task_handles: Vec::new(),
        };

        Ok(client)
    }

    /// Connect to DERP relays
    pub async fn connect_to_relays(&mut self) -> Result<()> {
        info!("Connecting to DERP relays");

        for relay_addr in &self.config.preferred_relays {
            if let Ok(addr) = relay_addr.parse::<SocketAddr>() {
                if let Err(e) = self.connect_to_relay(addr).await {
                    warn!("Failed to connect to relay {}: {}", addr, e);
                }
            }
        }

        Ok(())
    }

    /// Connect to a specific DERP relay
    async fn connect_to_relay(&self, addr: SocketAddr) -> Result<()> {
        info!("Connecting to DERP relay: {}", addr);

        let stream = TcpStream::connect(addr).await
            .map_err(|e| QuicError::Io(e.to_string()))?;

        // Perform handshake
        let mut stream = stream;
        let handshake = serde_json::to_vec(&self.local_node).unwrap();
        stream.write_all(&handshake).await
            .map_err(|e| QuicError::Io(e.to_string()))?;

        // Read response
        let mut buffer = [0u8; 1024];
        let bytes_read = stream.read(&mut buffer).await
            .map_err(|e| QuicError::Io(e.to_string()))?;

        if bytes_read == 0 {
            return Err(QuicError::Protocol(ProtocolError::InvalidState(
                "Server disconnected during handshake".to_string()
            )));
        }

        let relay = DerpRelay {
            server_addr: addr,
            stream: Arc::new(Mutex::new(stream)),
            state: RelayConnectionState::Connected,
            last_ping: Instant::now(),
            rtt: Duration::from_millis(50), // Default RTT
        };

        // Add to relays
        {
            let mut relays = self.relays.write().await;
            relays.insert(addr.to_string(), relay);
        }

        info!("Connected to DERP relay: {}", addr);
        Ok(())
    }

    /// Send message through DERP relay
    pub async fn send_message(&self, message: DerpMessage) -> Result<()> {
        debug!("Sending message {} to {}", message.id, message.destination);

        // Find best relay for the message
        let relay = self.select_best_relay().await?;

        // Send message through relay
        let serialized = serde_json::to_vec(&message)
            .map_err(|e| QuicError::Protocol(ProtocolError::InvalidPacket(
                format!("Failed to serialize message: {}", e)
            )))?;

        {
            let mut stream = relay.stream.lock().await;
            stream.write_all(&serialized).await
                .map_err(|e| QuicError::Io(e.to_string()))?;
        }

        debug!("Message sent through relay");
        Ok(())
    }

    /// Select best relay for communication
    async fn select_best_relay(&self) -> Result<DerpRelay> {
        let relays = self.relays.read().await;

        if relays.is_empty() {
            return Err(QuicError::Protocol(ProtocolError::InvalidState(
                "No relays available".to_string()
            )));
        }

        // Find relay with lowest RTT
        let best_relay = relays.values()
            .min_by_key(|relay| relay.rtt)
            .unwrap();

        Ok((*best_relay).clone())
    }

    /// Connect to a specific peer through DERP relay
    pub async fn connect_to_peer(&self, peer_id: DerpNodeId, relay_addr: SocketAddr) -> Result<DerpConnection> {
        info!("Connecting to peer {} via DERP relay {}", peer_id, relay_addr);

        // Create a DERP connection for this specific peer
        let connection = DerpConnection {
            peer_id: peer_id.clone(),
            relay_addr,
            connection_id: format!("derp_conn_{}", rand::random::<u64>()),
            established_at: Instant::now(),
            last_activity: Instant::now(),
            bytes_sent: 0,
            bytes_received: 0,
            rtt: Duration::from_millis(50), // Default RTT
        };

        // In a real implementation, this would:
        // 1. Establish connection through the relay
        // 2. Perform handshake with the peer
        // 3. Set up forwarding rules

        debug!("DERP peer connection established: {} -> {}", peer_id, relay_addr);
        Ok(connection)
    }
}

/// DERP connection representation
#[derive(Debug, Clone)]
pub struct DerpConnection {
    pub peer_id: DerpNodeId,
    pub relay_addr: SocketAddr,
    pub connection_id: String,
    pub established_at: Instant,
    pub last_activity: Instant,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub rtt: Duration,
}

impl RateLimiter {
    /// Check if action is allowed under rate limits
    pub fn is_allowed(&mut self, message_size: usize) -> bool {
        let now = Instant::now();

        // Reset window if needed
        if now.duration_since(self.window_start) >= Duration::from_secs(1) {
            self.messages_in_window = 0;
            self.bytes_in_window = 0;
            self.window_start = now;
        }

        // Check limits
        if self.messages_in_window >= self.config.messages_per_second {
            return false;
        }

        if self.bytes_in_window + message_size as u64 > self.config.bytes_per_second {
            return false;
        }

        // Update counters
        self.messages_in_window += 1;
        self.bytes_in_window += message_size as u64;

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_derp_server_creation() {
        let config = DerpServerConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            region: "test".to_string(),
            max_clients: 100,
            client_timeout: Duration::from_secs(300),
            message_ttl: Duration::from_secs(60),
            enable_persistence: false,
            max_message_size: 1024 * 1024,
            rate_limits: RateLimitConfig {
                messages_per_second: 100,
                bytes_per_second: 1024 * 1024,
                burst_allowance: 10,
            },
            tls_config: None,
        };

        let server = DerpServer::new(config).await;
        assert!(server.is_ok());
    }

    #[tokio::test]
    async fn test_derp_client_creation() {
        let config = DerpClientConfig {
            preferred_relays: vec!["127.0.0.1:8080".to_string()],
            home_region: "test".to_string(),
            retry_attempts: 3,
            connection_timeout: Duration::from_secs(10),
            keepalive_interval: Duration::from_secs(30),
            enable_mesh_mode: true,
            nat_traversal_timeout: Duration::from_secs(30),
        };

        let node_info = DerpNodeInfo {
            id: DerpNodeId("test-node".to_string()),
            public_key: "test-key".to_string(),
            endpoints: vec!["127.0.0.1:8081".parse().unwrap()],
            capabilities: NodeCapabilities {
                supports_direct: true,
                supports_mesh: true,
                supports_containers: false,
                max_message_size: 1024 * 1024,
            },
            last_seen: SystemTime::now(),
            metadata: HashMap::new(),
        };

        let client = DerpClient::new(config, node_info).await;
        assert!(client.is_ok());
    }

    #[test]
    fn test_rate_limiter() {
        let config = RateLimitConfig {
            messages_per_second: 10,
            bytes_per_second: 1024,
            burst_allowance: 5,
        };

        let mut limiter = RateLimiter {
            messages_in_window: 0,
            bytes_in_window: 0,
            window_start: Instant::now(),
            config,
        };

        // Should allow initial messages
        assert!(limiter.is_allowed(100));
        assert!(limiter.is_allowed(100));

        // Should deny when rate limit exceeded
        for _ in 0..20 {
            limiter.is_allowed(10);
        }
        assert!(!limiter.is_allowed(10));
    }
}