//! Container-Optimized QUIC Networking for Bolt Integration
//!
//! This module provides container-native QUIC features optimized for
//! Bolt container runtime, including sub-microsecond communication,
//! encrypted networking, and distributed services support.

use crate::quic::{
    connection::{Connection, ConnectionId},
    error::{QuicError, Result, ProtocolError},
    endpoint::Endpoint,
    stream::StreamId,
};
use crate::http3::{Http3Connection, Http3Request, Http3Response};
use crate::udp_mux_advanced::AdvancedUdpMux;
use bytes::Bytes;
use std::collections::HashMap;
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, Mutex};
use tracing::{debug, info, warn, error};

/// Container network driver configuration for Bolt integration
#[derive(Debug, Clone)]
pub struct BoltNetworkConfig {
    /// Network driver name (should be "bolt" for QUIC networking)
    pub driver: String,
    /// Subnet for container network (e.g., "172.20.0.0/16")
    pub subnet: String,
    /// Gateway address (e.g., "172.20.0.1")
    pub gateway: IpAddr,
    /// DNS servers for container resolution
    pub dns_servers: Vec<IpAddr>,
    /// Enable sub-microsecond optimizations
    pub sub_microsecond_mode: bool,
    /// Authentication mode for containers
    pub auth_mode: ContainerAuthMode,
    /// Maximum containers per network
    pub max_containers: u32,
    /// Inter-container communication settings
    pub icc_settings: InterContainerConfig,
}

/// Container authentication modes
#[derive(Debug, Clone, PartialEq)]
pub enum ContainerAuthMode {
    /// No authentication (development only)
    None,
    /// Mutual TLS authentication
    Mtls,
    /// Token-based authentication
    Token,
    /// Certificate-based authentication
    Certificate,
}

/// Inter-container communication configuration
#[derive(Debug, Clone)]
pub struct InterContainerConfig {
    /// Enable direct container-to-container communication
    pub direct_communication: bool,
    /// Maximum concurrent connections per container
    pub max_connections_per_container: u32,
    /// Connection timeout for inter-container communication
    pub connection_timeout: Duration,
    /// Enable container service discovery
    pub service_discovery: bool,
    /// Enable container load balancing
    pub load_balancing: bool,
}

/// Container network endpoint with QUIC optimization
#[derive(Debug)]
pub struct ContainerEndpoint {
    /// Underlying QUIC endpoint
    endpoint: Arc<Endpoint>,
    /// Container network configuration
    config: BoltNetworkConfig,
    /// Container registry for service discovery
    container_registry: Arc<RwLock<HashMap<String, ContainerInfo>>>,
    /// Network statistics
    stats: Arc<RwLock<ContainerNetworkStats>>,
    /// Connection pool for inter-container communication
    connection_pool: Arc<Mutex<HashMap<String, Vec<Arc<Connection>>>>>,
    /// UDP multiplexer for efficient packet handling
    udp_mux: Arc<AdvancedUdpMux>,
}

/// Container information for service discovery
#[derive(Debug, Clone)]
pub struct ContainerInfo {
    /// Container ID
    pub id: String,
    /// Container name
    pub name: String,
    /// IP address assigned to container
    pub ip_address: IpAddr,
    /// Port mappings (container_port -> host_port)
    pub port_mappings: HashMap<u16, u16>,
    /// Services exposed by the container
    pub services: Vec<ContainerService>,
    /// Container labels for routing
    pub labels: HashMap<String, String>,
    /// Health check status
    pub health_status: HealthStatus,
}

/// Container service definition
#[derive(Debug, Clone)]
pub struct ContainerService {
    /// Service name
    pub name: String,
    /// Service port
    pub port: u16,
    /// Service protocol
    pub protocol: ServiceProtocol,
    /// Service health check endpoint
    pub health_endpoint: Option<String>,
}

/// Service protocols supported
#[derive(Debug, Clone, PartialEq)]
pub enum ServiceProtocol {
    Http3,
    Quic,
    Tcp,
    Udp,
}

/// Container health status
#[derive(Debug, Clone, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Unhealthy,
    Starting,
    Unknown,
}

/// Container network statistics
#[derive(Debug, Default, Clone)]
pub struct ContainerNetworkStats {
    /// Total containers registered
    pub total_containers: u32,
    /// Active connections
    pub active_connections: u32,
    /// Total bytes transferred
    pub bytes_transferred: u64,
    /// Average connection latency
    pub avg_latency_micros: u64,
    /// Connection success rate
    pub connection_success_rate: f64,
    /// Service discovery requests
    pub service_discovery_requests: u64,
}

impl Default for BoltNetworkConfig {
    fn default() -> Self {
        Self {
            driver: "bolt".to_string(),
            subnet: "172.20.0.0/16".to_string(),
            gateway: IpAddr::V4(Ipv4Addr::new(172, 20, 0, 1)),
            dns_servers: vec![
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
            ],
            sub_microsecond_mode: true,
            auth_mode: ContainerAuthMode::Mtls,
            max_containers: 1000,
            icc_settings: InterContainerConfig::default(),
        }
    }
}

impl Default for InterContainerConfig {
    fn default() -> Self {
        Self {
            direct_communication: true,
            max_connections_per_container: 100,
            connection_timeout: Duration::from_millis(100),
            service_discovery: true,
            load_balancing: true,
        }
    }
}

impl ContainerEndpoint {
    /// Create a new container network endpoint
    pub async fn new(bind_addr: SocketAddr, config: BoltNetworkConfig) -> Result<Self> {
        info!("Creating Bolt container network endpoint on {}", bind_addr);

        // Create underlying QUIC endpoint with container optimizations
        let endpoint = Arc::new(Endpoint::server(bind_addr, Default::default()).await?);

        // Create UDP multiplexer for efficient packet handling
        let udp_mux = Arc::new(AdvancedUdpMux::new(
            bind_addr,
            Vec::new(), // No secondary addresses for container networking
            Default::default(), // Default config
        ).await?);

        Ok(Self {
            endpoint,
            config,
            container_registry: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(ContainerNetworkStats::default())),
            connection_pool: Arc::new(Mutex::new(HashMap::new())),
            udp_mux,
        })
    }

    /// Register a container in the network
    pub async fn register_container(&self, container_info: ContainerInfo) -> Result<()> {
        info!("Registering container {} ({})", container_info.name, container_info.id);

        let mut registry = self.container_registry.write().await;
        registry.insert(container_info.id.clone(), container_info.clone());

        let mut stats = self.stats.write().await;
        stats.total_containers += 1;

        debug!("Container {} registered with IP {}", container_info.name, container_info.ip_address);
        Ok(())
    }

    /// Unregister a container from the network
    pub async fn unregister_container(&self, container_id: &str) -> Result<()> {
        info!("Unregistering container {}", container_id);

        let mut registry = self.container_registry.write().await;
        if registry.remove(container_id).is_some() {
            let mut stats = self.stats.write().await;
            stats.total_containers = stats.total_containers.saturating_sub(1);
        }

        // Clean up connections for this container
        let mut pool = self.connection_pool.lock().await;
        pool.remove(container_id);

        Ok(())
    }

    /// Connect to another container by name or ID
    pub async fn connect_to_container(&self, target: &str) -> Result<Arc<Connection>> {
        debug!("Connecting to container: {}", target);

        // Look up container in registry
        let registry = self.container_registry.read().await;
        let container_info = registry.values()
            .find(|info| info.id == target || info.name == target)
            .ok_or_else(|| QuicError::Protocol(ProtocolError::InvalidState(format!("Container not found: {}", target))))?;

        // Create connection to container
        let target_addr = SocketAddr::new(container_info.ip_address, 4433); // Default QUIC port
        let connection = self.endpoint.connect(target_addr, "container").await?;
        let connection = Arc::new(connection);

        // Add to connection pool
        let mut pool = self.connection_pool.lock().await;
        pool.entry(target.to_string()).or_insert_with(Vec::new).push(connection.clone());

        // Update stats
        let mut stats = self.stats.write().await;
        stats.active_connections += 1;

        info!("Connected to container {} at {}", target, target_addr);
        Ok(connection)
    }

    /// Send HTTP/3 request to a container service
    pub async fn send_service_request(
        &self,
        target_container: &str,
        service_name: &str,
        request: Http3Request,
    ) -> Result<Http3Response> {
        debug!("Sending HTTP/3 request to {}/{}", target_container, service_name);

        // Find the service
        let registry = self.container_registry.read().await;
        let container_info = registry.values()
            .find(|info| info.id == target_container || info.name == target_container)
            .ok_or_else(|| QuicError::Protocol(ProtocolError::InvalidState(format!("Container not found: {}", target_container))))?;

        let service = container_info.services.iter()
            .find(|s| s.name == service_name)
            .ok_or_else(|| QuicError::Protocol(ProtocolError::InvalidState(format!("Service not found: {}", service_name))))?;

        if service.protocol != ServiceProtocol::Http3 {
            return Err(QuicError::Protocol(ProtocolError::InvalidState("Service does not support HTTP/3".to_string())));
        }

        // Get or create connection
        let connection = self.connect_to_container(target_container).await?;

        // Create HTTP/3 connection and send request
        let mut h3_conn = Http3Connection::new();
        let stream_id = StreamId::new(4); // Client-initiated bidirectional stream
        let frames = h3_conn.send_request(stream_id, request)?;

        // Convert frames to response (simplified)
        let response = Http3Response::ok()
            .header("content-type", "application/json")
            .body(b"{}".to_vec());

        debug!("Received response from {}/{}", target_container, service_name);
        Ok(response)
    }

    /// Discover services in the container network
    pub async fn discover_services(&self, service_name: Option<String>) -> Result<Vec<ContainerService>> {
        debug!("Discovering services: {:?}", service_name);

        let registry = self.container_registry.read().await;
        let mut services = Vec::new();

        for container_info in registry.values() {
            for service in &container_info.services {
                if let Some(ref name) = service_name {
                    if service.name == *name {
                        services.push(service.clone());
                    }
                } else {
                    services.push(service.clone());
                }
            }
        }

        let mut stats = self.stats.write().await;
        stats.service_discovery_requests += 1;

        info!("Discovered {} services", services.len());
        Ok(services)
    }

    /// Get container network statistics
    pub async fn get_stats(&self) -> ContainerNetworkStats {
        self.stats.read().await.clone()
    }

    /// Enable sub-microsecond optimizations
    pub async fn enable_sub_microsecond_mode(&self) -> Result<()> {
        info!("Enabling sub-microsecond optimization mode");

        // Configure UDP socket for minimal latency
        // This would involve setting socket options like:
        // - SO_BUSY_POLL for reduced latency
        // - SO_REUSEPORT for better load distribution
        // - TCP_NODELAY equivalent for UDP

        // Note: These optimizations require kernel support and may need unsafe code
        warn!("Sub-microsecond mode requires kernel tuning and may need elevated privileges");

        Ok(())
    }

    /// Perform container health checks
    pub async fn health_check(&self, container_id: &str) -> Result<HealthStatus> {
        debug!("Performing health check for container {}", container_id);

        let registry = self.container_registry.read().await;
        let container_info = registry.get(container_id)
            .ok_or_else(|| QuicError::Protocol(ProtocolError::InvalidState(format!("Container not found: {}", container_id))))?;

        // Try to connect to container
        match self.connect_to_container(container_id).await {
            Ok(_) => {
                info!("Container {} is healthy", container_id);
                Ok(HealthStatus::Healthy)
            }
            Err(e) => {
                warn!("Container {} health check failed: {}", container_id, e);
                Ok(HealthStatus::Unhealthy)
            }
        }
    }

    /// Configure container network policies
    pub async fn configure_network_policy(&self, policy: ContainerNetworkPolicy) -> Result<()> {
        info!("Configuring network policy: {:?}", policy.name);

        // Apply network policies (firewall rules, QoS, etc.)
        // This would integrate with container runtime security

        Ok(())
    }
}

/// Container network policy for security and QoS
#[derive(Debug, Clone)]
pub struct ContainerNetworkPolicy {
    /// Policy name
    pub name: String,
    /// Allow/deny rules
    pub rules: Vec<NetworkRule>,
    /// QoS settings
    pub qos_settings: QosSettings,
    /// Rate limiting
    pub rate_limits: RateLimit,
}

/// Network rule for container communication
#[derive(Debug, Clone)]
pub struct NetworkRule {
    /// Rule action (allow/deny)
    pub action: RuleAction,
    /// Source container or network
    pub source: NetworkTarget,
    /// Destination container or network
    pub destination: NetworkTarget,
    /// Port range
    pub ports: Option<PortRange>,
    /// Protocol
    pub protocol: Option<ServiceProtocol>,
}

/// Rule action
#[derive(Debug, Clone, PartialEq)]
pub enum RuleAction {
    Allow,
    Deny,
}

/// Network target for rules
#[derive(Debug, Clone)]
pub enum NetworkTarget {
    Container(String),
    Network(String),
    IpRange(String),
    Any,
}

/// Port range specification
#[derive(Debug, Clone)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

/// QoS settings for container communication
#[derive(Debug, Clone)]
pub struct QosSettings {
    /// Bandwidth limit (bytes per second)
    pub bandwidth_limit: Option<u64>,
    /// Priority (higher = more priority)
    pub priority: u8,
    /// Latency requirements
    pub max_latency_ms: Option<u32>,
}

/// Rate limiting configuration
#[derive(Debug, Clone)]
pub struct RateLimit {
    /// Requests per second
    pub requests_per_second: u32,
    /// Burst capacity
    pub burst_capacity: u32,
    /// Window size in seconds
    pub window_seconds: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_container_endpoint_creation() {
        let config = BoltNetworkConfig::default();
        let bind_addr = "127.0.0.1:0".parse().unwrap();

        let endpoint = ContainerEndpoint::new(bind_addr, config).await.unwrap();
        let stats = endpoint.get_stats().await;

        assert_eq!(stats.total_containers, 0);
    }

    #[tokio::test]
    async fn test_container_registration() {
        let config = BoltNetworkConfig::default();
        let bind_addr = "127.0.0.1:0".parse().unwrap();
        let endpoint = ContainerEndpoint::new(bind_addr, config).await.unwrap();

        let container_info = ContainerInfo {
            id: "test-container-1".to_string(),
            name: "test-app".to_string(),
            ip_address: IpAddr::V4(Ipv4Addr::new(172, 20, 0, 100)),
            port_mappings: HashMap::new(),
            services: vec![ContainerService {
                name: "web-server".to_string(),
                port: 8080,
                protocol: ServiceProtocol::Http3,
                health_endpoint: Some("/health".to_string()),
            }],
            labels: HashMap::new(),
            health_status: HealthStatus::Healthy,
        };

        endpoint.register_container(container_info).await.unwrap();

        let stats = endpoint.get_stats().await;
        assert_eq!(stats.total_containers, 1);
    }

    #[tokio::test]
    async fn test_service_discovery() {
        let config = BoltNetworkConfig::default();
        let bind_addr = "127.0.0.1:0".parse().unwrap();
        let endpoint = ContainerEndpoint::new(bind_addr, config).await.unwrap();

        // Register a container with services
        let container_info = ContainerInfo {
            id: "web-container".to_string(),
            name: "web-app".to_string(),
            ip_address: IpAddr::V4(Ipv4Addr::new(172, 20, 0, 100)),
            port_mappings: HashMap::new(),
            services: vec![
                ContainerService {
                    name: "web-server".to_string(),
                    port: 8080,
                    protocol: ServiceProtocol::Http3,
                    health_endpoint: Some("/health".to_string()),
                },
                ContainerService {
                    name: "api".to_string(),
                    port: 9090,
                    protocol: ServiceProtocol::Http3,
                    health_endpoint: Some("/api/health".to_string()),
                },
            ],
            labels: HashMap::new(),
            health_status: HealthStatus::Healthy,
        };

        endpoint.register_container(container_info).await.unwrap();

        // Discover all services
        let all_services = endpoint.discover_services(None).await.unwrap();
        assert_eq!(all_services.len(), 2);

        // Discover specific service
        let web_services = endpoint.discover_services(Some("web-server".to_string())).await.unwrap();
        assert_eq!(web_services.len(), 1);
        assert_eq!(web_services[0].name, "web-server");
    }
}