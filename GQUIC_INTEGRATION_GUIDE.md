# GQUIC v0.2.0 - Complete Integration Guide

> **🎉 GQUIC v0.2.0 is now feature-complete!** This guide covers integration with the fully-implemented, production-ready QUIC library optimized for crypto applications.

## 📋 Table of Contents
- [Quick Start](#quick-start)
- [Core Features](#core-features)
- [API Migration Guide](#api-migration-guide)
- [Configuration](#configuration)
- [Integration Examples](#integration-examples)
- [Performance Tuning](#performance-tuning)
- [Security Best Practices](#security-best-practices)
- [Monitoring & Observability](#monitoring--observability)
- [Troubleshooting](#troubleshooting)

## 🚀 Quick Start

### Dependencies

```toml
[dependencies]
gquic = { path = "../gquic", features = ["crypto-optimized"] }
tokio = { version = "1.0", features = ["full"] }
anyhow = "1.0"
tracing = "0.1"
```

### Basic Server Setup

```rust
use gquic::prelude::*;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    // Create server with crypto-optimized configuration
    let config = GquicConfig {
        bind_address: Some("0.0.0.0:8443".parse()?),
        max_connections: Some(10000),
        enable_datagrams: Some(true),
        enable_0rtt: Some(true),
        cipher_suites: Some(vec![
            "TLS_AES_256_GCM_SHA384".to_string(),
            "TLS_CHACHA20_POLY1305_SHA256".to_string(),
        ]),
        alpn_protocols: Some(vec![
            "crypto-quic/1.0".to_string(),
            "h3".to_string(),
        ]),
        ..Default::default()
    };

    // Validate configuration
    let validator = ConfigValidator::new();
    let validation_result = validator.validate_config(&config);
    if !validation_result.valid {
        eprintln!("❌ Configuration validation failed:");
        for issue in validation_result.issues {
            eprintln!("  - {}: {}", issue.severity, issue.message);
        }
        return Err(anyhow::anyhow!("Invalid configuration"));
    }

    let server = QuicServer::builder()
        .with_config(config)
        .with_certificate_path("cert.pem")?
        .with_private_key_path("key.pem")?
        .with_handler(Arc::new(CryptoHandler::new()))
        .build()?;

    println!("🚀 GQUIC server starting on port 8443");
    server.run().await
}
```

### Basic Client Setup

```rust
use gquic::prelude::*;

#[tokio::main]
async fn main() -> Result<()> {
    let client = QuicClient::builder()
        .with_server_name("crypto-exchange.com")
        .with_alpn_protocols(vec!["crypto-quic/1.0".to_string()])
        .with_0rtt_enabled(true)
        .build()?;

    let connection = client.connect("crypto-exchange.com:8443").await?;
    
    // Use real-time datagrams for market data
    let datagram_manager = connection.datagram_manager();
    let realtime_sender = datagram_manager.create_realtime_sender();
    
    // Send market data update
    realtime_sender.send_market_data("BTC/USD", b"price:65000.00").await?;
    
    Ok(())
}
```

## 🎯 Core Features

### ✅ Implemented Features

| Feature | Status | Description |
|---------|--------|-------------|
| **Core QUIC Protocol** | ✅ Complete | RFC 9000 compliant implementation |
| **TLS 1.3 Integration** | ✅ Complete | Strong cryptography with perfect forward secrecy |
| **0-RTT Support** | ✅ Complete | Low-latency resumption with anti-replay protection |
| **Connection Migration** | ✅ Complete | Mobile network support with path validation |
| **QUIC Datagrams** | ✅ Complete | Unreliable messaging for real-time data |
| **Stream Scheduling** | ✅ Complete | Priority-based with anti-starvation |
| **Congestion Control** | ✅ Complete | Multiple algorithms (NewReno, CUBIC, BBR) |
| **Loss Recovery** | ✅ Complete | RFC 9002 compliant packet loss detection |
| **Bandwidth Estimation** | ✅ Complete | Adaptive network performance monitoring |
| **Connection ID Rotation** | ✅ Complete | Privacy protection and tracking prevention |
| **Event System** | ✅ Complete | Real-time monitoring and automation |
| **Comprehensive Metrics** | ✅ Complete | Prometheus export and health monitoring |
| **ALPN Support** | ✅ Complete | Multiple protocol negotiation |
| **Configuration Validation** | ✅ Complete | Security-focused validation system |
| **Graceful Shutdown** | ✅ Complete | Clean connection and resource cleanup |

### 🔒 Security Features

- **TLS 1.3 Only**: No downgrade attacks
- **Perfect Forward Secrecy**: Key rotation and secure key exchange
- **Connection ID Rotation**: Privacy protection against tracking
- **Anti-Replay Protection**: 0-RTT security mechanisms
- **DDoS Protection**: Rate limiting and connection management
- **Certificate Validation**: Strong PKI integration

### ⚡ Performance Features

- **Multiple Congestion Control**: NewReno, CUBIC, BBR algorithms
- **Bandwidth Adaptation**: Real-time network condition monitoring
- **Priority Scheduling**: Critical data gets priority (market data > orders > logs)
- **0-RTT Resumption**: Minimal latency for repeat connections
- **Efficient Packing**: Optimized frame and packet structure
- **Memory Optimization**: Connection pooling and resource management

### 🎯 Crypto-Specific Features

- **Real-time Datagrams**: Perfect for market data streaming
- **Priority Streams**: Critical trading data gets precedence
- **Custom ALPN Protocols**: `crypto-quic/1.0` for trading protocols
- **Event-Driven Monitoring**: Real-time performance and security alerts
- **High-Frequency Trading Support**: Microsecond-level optimizations

## 🔄 API Migration Guide

### From Quinn to GQUIC

#### Stream Handling

**❌ Old Quinn Code:**
```rust
// Quinn API
while let Ok((send, recv)) = connection.bi_streams.accept().await {
    let mut send: SendStream = send;
    let mut recv: RecvStream = recv;
}
```

**✅ New GQUIC Code:**
```rust
// GQUIC API with type aliases for compatibility
while let Ok((send, recv)) = connection.accept_bi().await {
    let mut send: StreamWriter = send; // or use BiStream directly
    let mut recv: StreamReader = recv;
}
```

#### Connection Methods

**❌ Old Quinn Code:**
```rust
let remote_addr = connection.connection.remote_address();
```

**✅ New GQUIC Code:**
```rust
let remote_addr = connection.remote_address();
```

#### Error Handling

**❌ Old Quinn Code:**
```rust
match connection_error {
    quinn::ConnectionError::TimedOut => { /* handle timeout */ }
    quinn::ConnectionError::LocallyClosed => { /* handle close */ }
}
```

**✅ New GQUIC Code:**
```rust
match connection_error {
    QuicError::ConnectionTimeout => { /* handle timeout */ }
    QuicError::ConnectionClosed(_) => { /* handle close */ }
}
```

## ⚙️ Configuration

### Production Configuration Example

```rust
use gquic::config::*;
use std::time::Duration;

let config = GquicConfig {
    // Network settings
    bind_address: Some("0.0.0.0:8443".parse().unwrap()),
    max_connections: Some(50000), // High-capacity trading system
    max_streams_per_connection: Some(1000),
    
    // Performance settings
    congestion_control_algorithm: Some("bbr".to_string()), // Best for trading
    initial_rtt: Some(Duration::from_millis(20)), // Optimistic for low-latency
    idle_timeout: Some(Duration::from_secs(300)),
    
    // Security settings
    verify_peer: Some(true),
    cipher_suites: Some(vec![
        "TLS_AES_256_GCM_SHA384".to_string(),
        "TLS_CHACHA20_POLY1305_SHA256".to_string(),
    ]),
    
    // 0-RTT settings (crypto-optimized)
    enable_0rtt: Some(true),
    max_0rtt_data: Some(16384), // 16KB limit for security
    
    // Privacy settings
    enable_connection_migration: Some(true),
    connection_id_rotation_interval: Some(Duration::from_secs(300)),
    enable_privacy_protection: Some(true),
    
    // Real-time features
    enable_datagrams: Some(true),
    max_datagram_size: Some(1200), // Conservative for most networks
    
    // ALPN protocols
    alpn_protocols: Some(vec![
        "crypto-quic/1.0".to_string(), // Custom crypto protocol
        "h3".to_string(),              // HTTP/3 fallback
        "wt".to_string(),              // WebTransport
    ]),
    
    ..Default::default()
};

// Always validate configuration before use
let validator = ConfigValidator::new();
let result = validator.validate_config(&config);
assert!(result.valid, "Configuration must be valid");
```

### Environment-Specific Configs

#### Development Environment
```rust
let dev_config = GquicConfig {
    verify_peer: Some(false), // Allow self-signed certs
    enable_0rtt: Some(false), // Disable for easier debugging
    max_connections: Some(100),
    ..Default::default()
};
```

#### High-Frequency Trading Environment
```rust
let hft_config = GquicConfig {
    congestion_control_algorithm: Some("bbr".to_string()),
    enable_datagrams: Some(true),
    max_datagram_size: Some(1200),
    initial_rtt: Some(Duration::from_millis(1)), // Very optimistic
    max_ack_delay: Some(Duration::from_millis(1)), // Minimal delay
    packet_threshold: Some(1), // Immediate loss detection
    enable_bandwidth_estimation: Some(true),
    ..Default::default()
};
```

## 💡 Integration Examples

### 1. Market Data Streaming Server

```rust
use gquic::prelude::*;
use gquic::quic::datagram::{DatagramManager, DatagramPriority};

struct MarketDataHandler {
    datagram_manager: Arc<DatagramManager>,
    subscribers: Arc<RwLock<HashMap<String, Vec<ConnectionId>>>>,
}

impl MarketDataHandler {
    async fn broadcast_price_update(&self, symbol: &str, price: f64) -> Result<()> {
        let data = format!("{}:{}", symbol, price);
        let subscribers = self.subscribers.read().await;
        
        if let Some(connections) = subscribers.get(symbol) {
            for connection_id in connections {
                // Use real-time datagrams for market data
                self.datagram_manager.send_datagram(
                    data.as_bytes().into(),
                    DatagramPriority::Critical, // Highest priority
                    Some(DatagramMetadata {
                        message_type: "market_data".to_string(),
                        sequence: self.get_next_sequence().await,
                        correlation_id: Some(symbol.to_string()),
                        attributes: HashMap::new(),
                    })
                ).await?;
            }
        }
        
        Ok(())
    }
}

#[async_trait::async_trait]
impl ConnectionHandler for MarketDataHandler {
    async fn handle_connection(&self, connection: Connection) -> Result<()> {
        // Set up real-time datagram handling
        let datagram_manager = connection.datagram_manager();
        let realtime_sender = datagram_manager.create_realtime_sender();
        
        // Handle subscription requests via streams
        while let Ok((mut send, mut recv)) = connection.accept_bi().await {
            let handler = self.clone();
            tokio::spawn(async move {
                // Read subscription request
                let mut buffer = vec![0u8; 1024];
                let len = recv.read(&mut buffer).await?;
                let request: SubscriptionRequest = serde_json::from_slice(&buffer[..len])?;
                
                // Add to subscribers
                handler.add_subscriber(request.symbol, connection.id()).await;
                
                // Send confirmation
                let response = SubscriptionResponse { success: true };
                let response_data = serde_json::to_vec(&response)?;
                send.write_all(&response_data).await?;
                
                Ok::<_, anyhow::Error>(())
            });
        }
        
        Ok(())
    }
}
```

### 2. Order Routing Client

```rust
use gquic::prelude::*;
use gquic::quic::scheduler::{StreamScheduler, Priority, StreamType};

struct OrderClient {
    connection: Connection,
    scheduler: StreamScheduler,
    order_sequence: AtomicU64,
}

impl OrderClient {
    async fn send_order(&self, order: TradingOrder) -> Result<OrderResponse> {
        // Use highest priority stream for orders
        let (mut send, mut recv) = self.connection.open_bi().await?;
        
        // Register stream with high priority
        self.scheduler.register_stream(
            send.id(),
            Priority::Critical,
            100, // High weight
            StreamType::Trading { order_type: order.order_type.clone() },
            Some(StreamDeadline {
                hard_deadline: Some(Instant::now() + Duration::from_millis(100)),
                soft_deadline: Some(Instant::now() + Duration::from_millis(50)),
                max_latency: Some(Duration::from_millis(10)),
            })
        )?;
        
        // Serialize and send order
        let order_data = bincode::serialize(&order)?;
        send.write_all(&order_data).await?;
        send.finish().await?;
        
        // Read response
        let mut response_buffer = vec![0u8; 4096];
        let len = recv.read(&mut response_buffer).await?;
        let response: OrderResponse = bincode::deserialize(&response_buffer[..len])?;
        
        Ok(response)
    }
    
    async fn send_market_data_request(&self, symbol: &str) -> Result<()> {
        // Use datagram for non-critical requests
        let datagram_manager = self.connection.datagram_manager();
        let request = MarketDataRequest { symbol: symbol.to_string() };
        let request_data = serde_json::to_vec(&request)?;
        
        datagram_manager.send_datagram(
            request_data.into(),
            DatagramPriority::Normal,
            None
        ).await?;
        
        Ok(())
    }
}
```

### 3. Event-Driven Monitoring

```rust
use gquic::quic::events::{EventManager, EventAutomation, AutomationRule, EventTrigger, AutomationAction};

async fn setup_monitoring(connection: Connection) -> Result<()> {
    let event_manager = Arc::new(EventManager::new(EventConfig::default()));
    let automation = EventAutomation::new(event_manager.clone());
    
    // Add automation rule for high latency
    let latency_rule = AutomationRule {
        id: "high_latency_alert".to_string(),
        name: "High Latency Alert".to_string(),
        enabled: true,
        trigger: EventTrigger::MetricThreshold {
            metric_name: "avg_rtt".to_string(),
            threshold: 100.0, // 100ms
            comparison: ThresholdComparison::GreaterThan,
        },
        actions: vec![
            AutomationAction::Log {
                level: "warn".to_string(),
                message: "High latency detected".to_string(),
            },
            AutomationAction::TriggerConnectionMigration {
                connection_id: connection.id(),
            },
        ],
        cooldown: Duration::from_secs(60),
        last_triggered: None,
    };
    
    automation.add_rule(latency_rule).await;
    
    // Subscribe to performance events
    let mut event_rx = event_manager.subscribe(
        "performance_monitor".to_string(),
        vec![EventType::RttChanged, EventType::BandwidthChanged],
        None,
    ).await?;
    
    // Process events
    tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            automation.process_event(&event).await.unwrap_or_else(|e| {
                eprintln!("Event processing error: {}", e);
            });
        }
    });
    
    Ok(())
}
```

## 🎛️ Performance Tuning

### Congestion Control Selection

```rust
// For high-frequency trading (low latency priority)
config.congestion_control_algorithm = Some("bbr".to_string());

// For bulk data transfer (throughput priority)
config.congestion_control_algorithm = Some("cubic".to_string());

// For variable networks (reliability priority)
config.congestion_control_algorithm = Some("newreno".to_string());
```

### Stream Priority Configuration

```rust
// Critical: Market data, emergency signals
scheduler.register_stream(stream_id, Priority::Critical, 100, StreamType::MarketData { symbol: "BTC".to_string() }, None)?;

// High: Trading orders, risk management
scheduler.register_stream(stream_id, Priority::High, 80, StreamType::Trading { order_type: "limit".to_string() }, None)?;

// Normal: Regular application data
scheduler.register_stream(stream_id, Priority::Normal, 50, StreamType::Application, None)?;

// Low: Bulk transfers, logs
scheduler.register_stream(stream_id, Priority::Low, 20, StreamType::BulkTransfer, None)?;
```

### Memory and Resource Tuning

```rust
let config = GquicConfig {
    max_memory_usage: Some(2 * 1024 * 1024 * 1024), // 2GB
    max_cpu_usage: Some(80.0), // 80% max CPU
    receive_buffer_size: Some(4 * 1024 * 1024), // 4MB
    send_buffer_size: Some(4 * 1024 * 1024), // 4MB
    max_file_descriptors: Some(65536),
    ..Default::default()
};
```

## 🔐 Security Best Practices

### Certificate Management

```rust
// Production certificate setup
let server = QuicServer::builder()
    .with_certificate_path("/etc/ssl/certs/trading-platform.pem")?
    .with_private_key_path("/etc/ssl/private/trading-platform.key")?
    .with_certificate_chain_validation(true)
    .with_ocsp_stapling(true)
    .build()?;
```

### Secure Configuration

```rust
let secure_config = GquicConfig {
    // Strong TLS settings
    cipher_suites: Some(vec![
        "TLS_AES_256_GCM_SHA384".to_string(),
        "TLS_CHACHA20_POLY1305_SHA256".to_string(),
    ]),
    verify_peer: Some(true),
    
    // Limit 0-RTT for security
    enable_0rtt: Some(true),
    max_0rtt_data: Some(8192), // Conservative limit
    
    // Enable privacy protection
    enable_privacy_protection: Some(true),
    connection_id_rotation_interval: Some(Duration::from_secs(300)),
    
    // Resource limits
    max_connections: Some(10000),
    max_streams_per_connection: Some(100),
    
    ..Default::default()
};
```

### Anti-DDoS Configuration

```rust
use gquic::security::DdosProtection;

let ddos_config = DdosConfig {
    enable_protection: true,
    max_connections_per_ip: 100,
    connection_rate_limit: RateLimit::new(1000, Duration::from_secs(60)),
    suspicious_threshold: 10,
    ban_duration: Duration::from_secs(3600),
};

let ddos_protection = DdosProtection::new(ddos_config);
```

## 📊 Monitoring & Observability

### Metrics Collection

```rust
use gquic::metrics::MetricsCollector;

let metrics = MetricsCollector::new(MetricsConfig::default());

// Record connection metrics
metrics.record_connection_established(connection_id, Some(handshake_duration)).await;
metrics.record_packet_sent(&connection_id, packet_size).await;
metrics.record_rtt(&connection_id, rtt_measurement).await;

// Get health report
let health = metrics.get_health_report().await;
println!("System health: {:?}", health.status);
println!("Active connections: {}", health.active_connections);
println!("Packet loss rate: {:.2}%", health.packet_loss_rate * 100.0);
```

### Prometheus Integration

```rust
use gquic::metrics::comprehensive::MetricsCollector;

let metrics = MetricsCollector::new(MetricsConfig::default());

// Export metrics for Prometheus
let prometheus_data = metrics.export_prometheus().await;
println!("{}", prometheus_data);

// Metrics include:
// - gquic_total_connections
// - gquic_active_connections
// - gquic_total_bytes_sent
// - gquic_total_bytes_received
// - gquic_packet_loss_rate
// - gquic_avg_rtt_seconds
// - gquic_throughput_mbps
```

### Real-time Health Monitoring

```rust
use gquic::observability::ObservabilityManager;

let obs_manager = ObservabilityManager::new(ObservabilityConfig::default());

// Set up health check
tokio::spawn(async move {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    loop {
        interval.tick().await;
        
        let health_status = metrics.perform_health_check().await;
        match health_status {
            HealthStatus::Critical => {
                eprintln!("🚨 CRITICAL: System health degraded");
                // Trigger alerts, failover, etc.
            }
            HealthStatus::Warning => {
                println!("⚠️  WARNING: Performance issues detected");
            }
            HealthStatus::Healthy => {
                println!("✅ System healthy");
            }
            _ => {}
        }
    }
});
```

## 🐛 Troubleshooting

### Common Issues and Solutions

#### 1. High Latency

**Symptoms:**
- RTT > 100ms
- Slow order execution
- Market data delays

**Solutions:**
```rust
// Use BBR congestion control
config.congestion_control_algorithm = Some("bbr".to_string());

// Optimize ACK delays
config.max_ack_delay = Some(Duration::from_millis(1));

// Enable connection migration
config.enable_connection_migration = Some(true);

// Check for network issues
let network_conditions = bandwidth_estimator.get_network_conditions(loss_rate).await;
match network_conditions.congestion_level {
    CongestionLevel::High | CongestionLevel::Severe => {
        // Trigger path migration or fallback
    }
    _ => {}
}
```

#### 2. Connection Drops

**Symptoms:**
- Frequent disconnections
- CONNECTION_CLOSE frames
- Handshake failures

**Solutions:**
```rust
// Increase idle timeout
config.idle_timeout = Some(Duration::from_secs(600));

// Enable keep-alive
config.keep_alive_interval = Some(Duration::from_secs(30));

// Check certificate validity
let validator = ConfigValidator::new();
let result = validator.validate_config(&config);
if !result.valid {
    for issue in result.issues {
        if issue.category == ValidationCategory::Security {
            eprintln!("Security issue: {}", issue.message);
        }
    }
}
```

#### 3. Poor Performance

**Symptoms:**
- Low throughput
- High CPU usage
- Memory leaks

**Solutions:**
```rust
// Optimize buffer sizes
config.receive_buffer_size = Some(8 * 1024 * 1024); // 8MB
config.send_buffer_size = Some(8 * 1024 * 1024);

// Tune connection limits
config.max_connections = Some(1000); // Reduce if needed
config.max_streams_per_connection = Some(50);

// Enable bandwidth estimation
config.enable_bandwidth_estimation = Some(true);

// Monitor resource usage
let stats = metrics.get_global_metrics().await;
if stats.memory_usage_mb > 1000.0 {
    eprintln!("High memory usage: {:.1}MB", stats.memory_usage_mb);
}
```

### Debug Logging

```rust
use tracing_subscriber;

// Enable debug logging
tracing_subscriber::fmt()
    .with_max_level(tracing::Level::DEBUG)
    .with_target(false)
    .init();

// GQUIC will log detailed information about:
// - Connection establishment
// - Packet processing
// - Stream operations
// - Security events
// - Performance metrics
```

### Performance Profiling

```bash
# CPU profiling
cargo build --release
perf record --call-graph=dwarf ./target/release/your-app
perf report

# Memory profiling
valgrind --tool=massif ./target/release/your-app
ms_print massif.out.*

# Network analysis
tcpdump -i any -w quic-traffic.pcap port 8443
wireshark quic-traffic.pcap
```

## 🔄 Upgrade Path

### From GQUIC v0.1.x to v0.2.0

1. **Update dependencies:**
```toml
[dependencies]
gquic = { path = "../gquic", version = "0.2.0" }
```

2. **Update imports:**
```rust
// Old
use gquic::{Connection, QuicServer};

// New  
use gquic::prelude::*;
```

3. **Configuration migration:**
```rust
// Old basic config
let server = QuicServer::new("0.0.0.0:8443")?;

// New comprehensive config
let config = GquicConfig::default();
let server = QuicServer::builder()
    .with_config(config)
    .build()?;
```

4. **Take advantage of new features:**
```rust
// Add real-time datagrams
let datagram_manager = connection.datagram_manager();
let realtime_sender = datagram_manager.create_realtime_sender();

// Add event monitoring
let event_manager = EventManager::new(EventConfig::default());

// Add metrics collection
let metrics = MetricsCollector::new(MetricsConfig::default());
```

## 📚 Additional Resources

- **API Documentation**: `cargo doc --open --package gquic`
- **Examples**: Check `examples/` directory for complete applications
- **Performance Benchmarks**: See `benches/` for performance comparisons
- **Security Audit**: Review `SECURITY.md` for security considerations

## 🤝 Support

For integration support:
1. Check this guide first
2. Review the API documentation
3. Look at example implementations
4. Check the troubleshooting section

The GQUIC v0.2.0 library is now production-ready for crypto applications with comprehensive features, security, and performance optimizations! 🚀

---

**Last Updated**: Latest version with all features implemented
**Version**: GQUIC v0.2.0
**Compatibility**: Tokio 1.0+, Rust 1.70+