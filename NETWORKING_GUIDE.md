# GQUIC Advanced Networking Guide

## 🌐 Complete Networking Architecture

GQUIC provides a comprehensive networking stack that combines QUIC protocol efficiency with advanced features for VPNs, container networking, and distributed applications.

## 📋 Table of Contents

- [Core Components](#core-components)
- [UDP Multiplexing](#udp-multiplexing)
- [Multi-Path QUIC](#multi-path-quic)
- [WireGuard Integration](#wireguard-integration)
- [DERP Relay System](#derp-relay-system)
- [Service Discovery](#service-discovery)
- [Container Networking](#container-networking)
- [Examples](#examples)

## Core Components

### Network Interface

The `NetworkInterface` provides a unified API for all networking operations:

```rust
use gquic::network::{NetworkInterface, NetworkConfig};

let config = NetworkConfig {
    primary_addr: "0.0.0.0:443".parse().unwrap(),
    additional_addrs: vec!["0.0.0.0:8443".parse().unwrap()],
    enable_path_discovery: true,
    enable_connection_migration: true,
    max_connections: 10000,
    ..Default::default()
};

let mut network = NetworkInterface::new(config).await?;
network.start().await?;

// Create a connection
let conn = network.create_connection(
    connection_id,
    peer_addr,
    None // Use default local address
).await?;
```

## UDP Multiplexing

Advanced UDP socket management with load balancing and failover:

```rust
use gquic::udp_mux_advanced::{AdvancedUdpMux, AdvancedMuxConfig, LoadBalanceStrategy};

let config = AdvancedMuxConfig {
    max_connections_per_socket: 10000,
    enable_migration: true,
    enable_multipath: true,
    enable_load_balancing: true,
    socket_recv_buffer_size: 2 * 1024 * 1024, // 2MB
    batch_size: 64,
    enable_gso: true, // Generic Segmentation Offload
    enable_gro: true, // Generic Receive Offload
    ..Default::default()
};

let mux = AdvancedUdpMux::new(
    primary_addr,
    vec![secondary_addr1, secondary_addr2],
    config
).await?;

// Send packet with optimal socket selection
mux.send_packet(packet_data, dest_addr).await?;
```

## Multi-Path QUIC

Utilize multiple network paths for improved performance and reliability:

```rust
use gquic::multipath::{MultiPathConnection, MultiPathConfig, SchedulerAlgorithm};

let config = MultiPathConfig {
    max_alternative_paths: 4,
    scheduler_algorithm: SchedulerAlgorithm::MinRtt,
    enable_path_migration: true,
    redundancy_factor: 0.1, // 10% redundancy
    enable_packet_duplication: true,
    ..Default::default()
};

let multipath = MultiPathConnection::new(
    connection_id,
    primary_local_addr,
    primary_remote_addr,
    config,
    udp_mux
).await?;

// Add alternative paths
multipath.add_path(alt_local_addr, alt_remote_addr).await?;

// Send data - automatically uses best path
multipath.send_packet(data).await?;
```

## WireGuard Integration

Hybrid QUIC+WireGuard for secure mesh networking:

```rust
use gquic::wireguard::{WireGuardManager, WireGuardConfig, WireGuardPeer};

let config = WireGuardConfig {
    enable_hybrid_mode: true,
    wireguard_port: 51820,
    quic_port: 51821,
    enable_key_rotation: true,
    key_rotation_interval: Duration::from_secs(3600),
    enable_container_mode: true, // For BOLT integration
    ..Default::default()
};

let wg_manager = WireGuardManager::new(config, quic_network).await?;
wg_manager.start().await?;

// Create WireGuard interface
let interface_name = wg_manager.create_interface(
    "gquic-wg0",
    "10.0.0.1".parse().unwrap(),
    "10.0.0.0/24"
).await?;

// Add peer
let peer = WireGuardPeer {
    public_key: "peer_public_key".to_string(),
    endpoint: Some("192.168.1.100:51820".parse().unwrap()),
    allowed_ips: vec!["10.0.0.2/32".to_string()],
    persistent_keepalive: Some(Duration::from_secs(25)),
    ..Default::default()
};

wg_manager.add_peer(&interface_name, peer).await?;

// Create hybrid tunnel
let tunnel_id = wg_manager.create_hybrid_tunnel(
    local_addr,
    remote_addr,
    "peer_public_key"
).await?;
```

## DERP Relay System

NAT traversal through encrypted relay servers:

```rust
use gquic::derp::{DerpServer, DerpClient, DerpServerConfig, DerpClientConfig};

// Server setup
let server_config = DerpServerConfig {
    listen_addr: "0.0.0.0:3478".parse().unwrap(),
    region: "us-west".to_string(),
    max_clients: 10000,
    client_timeout: Duration::from_secs(300),
    enable_persistence: true,
    ..Default::default()
};

let mut derp_server = DerpServer::new(server_config).await?;
derp_server.start().await?;

// Client setup
let client_config = DerpClientConfig {
    preferred_relays: vec!["relay1.example.com:3478".to_string()],
    home_region: "us-west".to_string(),
    enable_mesh_mode: true,
    nat_traversal_timeout: Duration::from_secs(30),
    ..Default::default()
};

let local_node = DerpNodeInfo {
    id: DerpNodeId("my-node".to_string()),
    public_key: "my_public_key".to_string(),
    endpoints: vec![local_addr],
    capabilities: NodeCapabilities {
        supports_direct: true,
        supports_mesh: true,
        supports_containers: true,
        max_message_size: 1024 * 1024,
    },
    last_seen: SystemTime::now(),
    metadata: HashMap::new(),
};

let mut derp_client = DerpClient::new(client_config, local_node).await?;
derp_client.connect_to_relays().await?;

// Send message through relay
let message = DerpMessage {
    id: uuid::Uuid::new_v4().to_string(),
    message_type: DerpMessageType::DataRelay,
    source: my_node_id,
    destination: peer_node_id,
    payload: data,
    timestamp: SystemTime::now(),
    ttl: Duration::from_secs(60),
    priority: MessagePriority::Normal,
};

derp_client.send_message(message).await?;
```

## Service Discovery

Comprehensive service discovery for distributed applications:

```rust
use gquic::discovery::{
    ServiceDiscoveryManager, DiscoveryConfig, ServiceInfo, ServiceType,
    ServiceEndpoint, EndpointProtocol, EndpointHealth
};

let config = DiscoveryConfig {
    node_id: "my-node".to_string(),
    enable_mdns: true,
    enable_dns_sd: true,
    enable_gossip: true,
    kubernetes_integration: true,
    container_mode: true,
    ..Default::default()
};

let mut discovery = ServiceDiscoveryManager::new(config).await?;
discovery.start().await?;

// Register a service
let service = ServiceInfo {
    id: ServiceId {
        name: "web-api".to_string(),
        namespace: Some("production".to_string()),
        version: Some("v1.2.3".to_string()),
    },
    service_type: ServiceType::Https,
    description: "Web API service".to_string(),
    endpoints: vec![ServiceEndpoint {
        address: "0.0.0.0:8080".parse().unwrap(),
        protocol: EndpointProtocol::Https,
        weight: 100,
        health: EndpointHealth::Healthy,
        metadata: HashMap::new(),
    }],
    health_check: Some(HealthCheck {
        check_type: HealthCheckType::Http {
            path: "/health".to_string(),
            expected_status: 200,
        },
        interval: Duration::from_secs(30),
        timeout: Duration::from_secs(5),
        unhealthy_threshold: 3,
        healthy_threshold: 2,
    }),
    registered_at: SystemTime::now(),
    ttl: Duration::from_secs(300),
    metadata: HashMap::new(),
    tags: HashSet::new(),
};

discovery.register_service(service).await?;

// Discover services
let query = ServiceQuery {
    name_pattern: "web-*".to_string(),
    namespace: Some("production".to_string()),
    required_tags: ["api", "v1"].iter().map(|s| s.to_string()).collect(),
    metadata_filters: HashMap::new(),
    require_healthy: true,
};

let discovered_services = discovery.discover_services(query).await?;
```

## Container Networking

Integration with BOLT container platform:

```rust
use gquic::wireguard::ContainerPeerInfo;

// Container peer for BOLT integration
let container_info = ContainerPeerInfo {
    container_id: "container-abc123".to_string(),
    namespace: "default".to_string(),
    assigned_ip: "10.244.1.100".parse().unwrap(),
    labels: [
        ("app".to_string(), "web-server".to_string()),
        ("version".to_string(), "v1.0".to_string()),
    ].iter().cloned().collect(),
    policies: vec![
        NetworkPolicy {
            name: "allow-ingress".to_string(),
            from: vec![PolicySelector {
                namespace_selector: Some([
                    ("name".to_string(), "frontend".to_string())
                ].iter().cloned().collect()),
                pod_selector: None,
                ip_block: None,
            }],
            to: vec![],
            ports: vec![PolicyPort {
                port: 8080,
                protocol: "TCP".to_string(),
            }],
            action: PolicyAction::Allow,
        }
    ],
};

let peer_config = WireGuardPeer {
    public_key: container_public_key,
    allowed_ips: vec!["10.244.1.100/32".to_string()],
    ..Default::default()
};

wg_manager.add_container_peer(container_info, peer_config).await?;
```

## Examples

### Mesh VPN Setup

```rust
use gquic::{mesh::GQuicMeshEndpoint, wireguard::WireGuardManager};

// Create mesh endpoint
let mesh_config = MeshConfig {
    node_id: "mesh-node-1".to_string(),
    listen_addr: "0.0.0.0:4433".parse().unwrap(),
    enable_discovery: true,
    max_peers: 100,
    ..Default::default()
};

let mesh = GQuicMeshEndpoint::new(mesh_config).await?;

// Add WireGuard for security
let wg_manager = WireGuardManager::new(wg_config, mesh.network()).await?;

// Add peer
mesh.add_peer("peer-1", "192.168.1.100:4433").await?;

// Send data
mesh.send_to_peer("peer-1", data).await?;
```

### HTTP/3 Proxy with Load Balancing

```rust
use gquic::proxy::{GQuicProxy, ProxyConfig};

let proxy_config = ProxyConfig {
    listen_addr: "0.0.0.0:443".parse().unwrap(),
    enable_http3: true,
    enable_load_balancing: true,
    enable_caching: true,
    max_connections: 10000,
    ..Default::default()
};

let proxy = GQuicProxy::new(proxy_config).await?;

// Add backend servers
proxy.add_upstream("backend-1", "10.0.1.100:8080").await?;
proxy.add_upstream("backend-2", "10.0.1.101:8080").await?;

proxy.start().await?;
```

### Performance Optimization

```rust
use gquic::zerocopy::{MemoryPool, PoolConfig};

// Zero-copy memory management
let pool_config = PoolConfig {
    chunk_size: 64 * 1024,
    initial_chunks: 1000,
    max_chunks: 10000,
    enable_simd: true,
    ..Default::default()
};

let memory_pool = MemoryPool::new(pool_config);

// Use with network operations
let buffer = memory_pool.get_buffer()?;
// ... use buffer for packet processing
memory_pool.return_buffer(buffer);
```

## Performance Tuning

### Socket Optimization

```rust
let mux_config = AdvancedMuxConfig {
    // Optimize for high throughput
    socket_recv_buffer_size: 16 * 1024 * 1024, // 16MB
    socket_send_buffer_size: 16 * 1024 * 1024, // 16MB
    batch_size: 128,

    // Enable hardware acceleration
    enable_gso: true,
    enable_gro: true,

    // Connection optimization
    max_connections_per_socket: 50000,
    enable_load_balancing: true,

    ..Default::default()
};
```

### Multi-Path Configuration

```rust
let multipath_config = MultiPathConfig {
    // Use multiple paths aggressively
    max_alternative_paths: 8,
    scheduler_algorithm: SchedulerAlgorithm::Weighted,

    // Enable redundancy for critical data
    redundancy_factor: 0.2, // 20% redundancy
    enable_packet_duplication: true,

    // Optimize for low latency
    path_probe_interval: Duration::from_secs(1),
    max_reorder_window: 200,

    ..Default::default()
};
```

## Monitoring and Observability

```rust
use gquic::observability::MetricsCollector;

let metrics = MetricsCollector::new();

// Get comprehensive statistics
let network_stats = network.stats().await;
let multipath_stats = multipath_conn.stats().await;
let discovery_stats = discovery.stats().await;

println!("Active connections: {}", network_stats.active_connections);
println!("Active paths: {}", multipath_stats.active_paths);
println!("Discovered services: {}", discovery_stats.services_discovered);

// Export to Prometheus
metrics.export_prometheus_metrics().await?;
```

## Troubleshooting

### Connection Issues

1. **Check UDP multiplexer stats**:
   ```rust
   let mux_stats = udp_mux.stats().await;
   println!("Socket utilization: {:.1}%", mux_stats.socket_utilization);
   ```

2. **Verify path health**:
   ```rust
   let active_paths = multipath.get_active_paths().await;
   for path_id in active_paths {
       let rtt = multipath.get_path_rtt(&path_id).await;
       println!("Path {} RTT: {:?}", path_id, rtt);
   }
   ```

3. **Check DERP connectivity**:
   ```rust
   let derp_stats = derp_client.stats().await;
   println!("Connected relays: {}", derp_stats.connected_relays);
   ```

### Performance Issues

1. **Monitor memory usage**:
   ```rust
   let pool_stats = memory_pool.stats();
   println!("Memory utilization: {:.1}%", pool_stats.utilization);
   ```

2. **Check discovery overhead**:
   ```rust
   let discovery_stats = discovery.stats().await;
   println!("Cache hit rate: {:.1}%",
            discovery_stats.cache_hits as f64 /
            (discovery_stats.cache_hits + discovery_stats.cache_misses) as f64 * 100.0);
   ```

This networking guide provides comprehensive coverage of GQUIC's advanced networking capabilities. The system is designed to be both powerful and easy to use, with sensible defaults for most use cases while allowing fine-grained control when needed.