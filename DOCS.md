# 📚 gquic Documentation

## Table of Contents

- [Overview](#overview)
- [Installation](#installation)
- [API Reference](#api-reference)
- [Configuration](#configuration)
- [Examples](#examples)
- [Performance Tuning](#performance-tuning)
- [Security](#security)
- [Troubleshooting](#troubleshooting)

## Overview

**gquic** is a high-performance QUIC transport library built for the GhostChain ecosystem. It provides:

- 🚀 Zero-copy packet processing
- 🔐 Integrated gcrypt cryptographic backend
- 📦 UDP multiplexing with connection pooling
- 🌐 Full HTTP/3 and gRPC-over-QUIC support
- ⚡ Async/await with tokio runtime
- 🧪 FFI compatibility for Zig integration

## Installation

### From Source

```bash
git clone https://github.com/ghostkellz/gquic
cd gquic
cargo build --release
```

### As a Dependency

Add to your `Cargo.toml`:

```toml
[dependencies]
gquic = { git = "https://github.com/ghostkellz/gquic", version = "0.1.0" }
```

### Features

- `default` - Includes gcrypt integration
- `gcrypt-integration` - Use gcrypt for cryptographic operations
- `metrics` - Enable performance metrics collection
- `ffi` - Enable FFI exports for Zig integration

## API Reference

### Client API

#### QuicClient

```rust
use gquic::prelude::*;

#[tokio::main]
async fn main() -> Result<()> {
    let client = QuicClient::builder()
        .server_name("ghostbridge.local".to_string())
        .with_alpn("h3")
        .max_idle_timeout(30_000)
        .build_client()?;

    let conn = client.connect("127.0.0.1:443".parse()?).await?;
    let mut stream = client.open_bi_stream(&conn).await?;
    
    stream.write_all(b"Hello, QUIC!").await?;
    let response = stream.read_to_end(1024).await?;
    
    Ok(())
}
```

#### Configuration Options

```rust
let config = QuicClientConfig::builder()
    .server_name("example.com".to_string())
    .with_alpn("h3")                    // HTTP/3
    .with_alpn("grpc")                  // gRPC-over-QUIC
    .max_idle_timeout(30_000)           // 30 seconds
    .max_bi_streams(100)                // Concurrent bidirectional streams
    .max_uni_streams(100)               // Concurrent unidirectional streams
    .keep_alive_interval(10_000)        // 10 seconds
    .build();
```

### Server API

#### QuicServer

```rust
use gquic::prelude::*;

#[tokio::main]
async fn main() -> Result<()> {
    let server = QuicServer::builder()
        .bind("0.0.0.0:443".parse()?)
        .with_self_signed_cert()?          // Development only
        // .with_tls_files("cert.pem", "key.pem")?  // Production
        .with_alpn("h3")
        .with_alpn("grpc")
        .max_concurrent_bidi_streams(1000)
        .max_idle_timeout(Duration::from_secs(30))
        .build()?;

    server.run().await?;
    Ok(())
}
```

#### Custom Connection Handler

```rust
use gquic::server::handler::ConnectionHandler;
use async_trait::async_trait;

struct MyHandler;

#[async_trait]
impl ConnectionHandler for MyHandler {
    async fn handle_connection(
        &self,
        connection: NewConnection,
        _config: Arc<QuicServerConfig>,
    ) -> Result<()> {
        // Handle incoming streams
        while let Ok((send, recv)) = connection.bi_streams.accept().await {
            tokio::spawn(async move {
                // Process stream
            });
        }
        Ok(())
    }
}

let server = QuicServer::builder()
    .bind("0.0.0.0:443".parse()?)
    .with_handler(Arc::new(MyHandler))
    .build()?;
```

### Connection Pool

```rust
use gquic::pool::{ConnectionPool, PoolConfig};

let pool_config = PoolConfig::builder()
    .max_connections_per_endpoint(10)
    .max_connection_age(Duration::from_secs(3600))
    .max_idle_time(Duration::from_secs(300))
    .enable_multiplexing(true)
    .build();

let pool = ConnectionPool::new(pool_config);

// Get or create connection
if let Some(conn) = pool.get_connection(addr).await {
    // Use existing connection
} else {
    // Create new connection
    let conn = client.connect(addr).await?;
    pool.return_connection(addr, conn.clone()).await;
}
```

### Cryptographic Backend

```rust
use gquic::crypto::{CryptoBackend, KeyType, default_backend};

// Use default backend (gcrypt if available, otherwise rustls)
let backend = default_backend();

// Generate keypair
let keypair = backend.generate_keypair(KeyType::Ed25519)?;

// Sign data
let signature = backend.sign(&keypair.private_key, b"message")?;

// Verify signature
let valid = backend.verify(&keypair.public_key, b"message", &signature)?;
```

### Metrics

```rust
use gquic::metrics::{METRICS, get_metrics};

// Record metrics
METRICS.connection_established();
METRICS.bytes_sent(1024);
METRICS.record_latency(Duration::from_millis(10));

// Get current metrics
#[cfg(feature = "metrics")]
{
    let metrics = get_metrics().get_metrics().await;
    println!("Active connections: {}", metrics.connection.active_connections);
    println!("Average latency: {:.2}ms", metrics.connection.average_latency_ms);
}
```

## Configuration

### TLS Configuration

#### Self-Signed Certificate (Development)

```rust
let server = QuicServer::builder()
    .with_self_signed_cert()?
    .build()?;
```

#### Production Certificates

```rust
let server = QuicServer::builder()
    .with_tls_files("/path/to/cert.pem", "/path/to/key.pem")?
    .build()?;
```

### Transport Configuration

```rust
let server = QuicServer::builder()
    .max_concurrent_bidi_streams(1000)
    .max_concurrent_uni_streams(1000)
    .max_idle_timeout(Duration::from_secs(30))
    .keep_alive_interval(Duration::from_secs(10))
    .build()?;
```

### ALPN Protocols

```rust
// HTTP/3
.with_alpn("h3")

// gRPC-over-QUIC
.with_alpn("grpc")

// Custom protocol
.with_alpn("ghostchain-v1")
```

## Examples

### Basic Echo Server

```rust
use gquic::prelude::*;
use gquic::server::handler::{ConnectionHandler, DefaultHandler};

#[tokio::main]
async fn main() -> Result<()> {
    let server = QuicServer::builder()
        .bind("0.0.0.0:8443".parse()?)
        .with_self_signed_cert()?
        .with_handler(Arc::new(DefaultHandler))  // Echo handler
        .build()?;

    println!("Echo server listening on :8443");
    server.run().await
}
```

### gRPC-over-QUIC Server

```rust
use gquic::prelude::*;
use gquic::proto::walletd::wallet_service_server::WalletServiceServer;
use tonic::transport::Server;

#[tokio::main]
async fn main() -> Result<()> {
    let wallet_service = MyWalletService::new();
    
    let server = QuicServer::builder()
        .bind("0.0.0.0:9090".parse()?)
        .with_tls_files("cert.pem", "key.pem")?
        .with_alpn("grpc")
        .build()?;

    // TODO: Integrate with tonic for gRPC handling
    server.run().await
}
```

### Connection Multiplexing

```rust
use gquic::prelude::*;

#[tokio::main]
async fn main() -> Result<()> {
    let client = QuicClient::builder()
        .server_name("api.ghostchain.org".to_string())
        .build_client()?;

    let conn = client.connect("api.ghostchain.org:443".parse()?).await?;

    // Open multiple concurrent streams
    let mut handles = vec![];
    for i in 0..10 {
        let client = client.clone();
        let conn = conn.clone();
        
        handles.push(tokio::spawn(async move {
            let mut stream = client.open_bi_stream(&conn).await?;
            stream.write_all(format!("Request {}", i).as_bytes()).await?;
            stream.read_to_end(1024).await
        }));
    }

    // Wait for all requests
    for handle in handles {
        let response = handle.await??;
        println!("Response: {}", String::from_utf8_lossy(&response));
    }

    Ok(())
}
```

## Performance Tuning

### Connection Pool Optimization

```rust
let pool_config = PoolConfig::builder()
    .max_connections_per_endpoint(50)     // Higher for busy endpoints
    .max_connection_age(Duration::from_secs(7200))  // 2 hours
    .max_idle_time(Duration::from_secs(300))        // 5 minutes
    .cleanup_interval(Duration::from_secs(30))      // More frequent cleanup
    .enable_multiplexing(true)
    .max_concurrent_streams(200)          // Higher concurrency
    .build();
```

### Transport Optimization

```rust
let server = QuicServer::builder()
    .max_concurrent_bidi_streams(2000)    // Scale with server capacity
    .max_concurrent_uni_streams(2000)
    .max_idle_timeout(Duration::from_secs(60))  // Longer for persistent connections
    .keep_alive_interval(Duration::from_secs(15))  // More frequent keep-alive
    .build()?;
```

### Operating System Tuning

```bash
# Increase UDP buffer sizes
echo 'net.core.rmem_max = 134217728' >> /etc/sysctl.conf
echo 'net.core.wmem_max = 134217728' >> /etc/sysctl.conf
echo 'net.core.rmem_default = 16777216' >> /etc/sysctl.conf
echo 'net.core.wmem_default = 16777216' >> /etc/sysctl.conf

# Apply changes
sysctl -p
```

## Security

### TLS Configuration

Always use proper TLS certificates in production:

```rust
// ❌ Don't use in production
.with_self_signed_cert()?

// ✅ Use proper certificates
.with_tls_files("/etc/ssl/certs/server.crt", "/etc/ssl/private/server.key")?
```

### Key Management

Use secure key generation and storage:

```rust
// Generate secure keypairs
let backend = default_backend();
let keypair = backend.generate_keypair(KeyType::Ed25519)?;

// Store keys securely (example)
let encrypted_key = encrypt_key(&keypair.private_key, &master_key)?;
store_key_securely(&encrypted_key)?;
```

### Network Security

- Always use TLS/QUIC encryption
- Implement proper authentication
- Rate limit connections
- Use firewall rules
- Monitor for suspicious activity

## Troubleshooting

### Common Issues

#### Connection Failures

```rust
// Check server is running and accessible
let result = client.connect(addr).await;
match result {
    Err(e) if e.to_string().contains("Connection refused") => {
        eprintln!("Server not running on {}", addr);
    }
    Err(e) if e.to_string().contains("timeout") => {
        eprintln!("Connection timeout - check network/firewall");
    }
    Err(e) => eprintln!("Connection error: {}", e),
    Ok(_) => println!("Connected successfully"),
}
```

#### TLS Certificate Issues

```rust
// Verify certificate files exist and are readable
if !std::path::Path::new("cert.pem").exists() {
    eprintln!("Certificate file not found");
}

// Check certificate validity
let server = QuicServer::builder()
    .with_tls_files("cert.pem", "key.pem")
    .map_err(|e| {
        eprintln!("TLS configuration error: {}", e);
        e
    })?;
```

#### Performance Issues

```rust
// Enable metrics to diagnose issues
#[cfg(feature = "metrics")]
{
    let metrics = get_metrics().get_metrics().await;
    
    if metrics.connection.failed_connections > 0 {
        println!("Connection failures: {}", metrics.connection.failed_connections);
    }
    
    if metrics.connection.average_latency_ms > 100.0 {
        println!("High latency detected: {:.2}ms", metrics.connection.average_latency_ms);
    }
}
```

### Debug Logging

Enable detailed logging:

```rust
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

tracing_subscriber::registry()
    .with(tracing_subscriber::fmt::layer())
    .with(tracing_subscriber::filter::LevelFilter::DEBUG)
    .init();
```

### Environment Variables

```bash
# Enable debug logging
RUST_LOG=gquic=debug,quinn=debug

# Increase log verbosity
RUST_LOG=trace

# Custom configuration
GQUIC_BIND_ADDR=0.0.0.0:8443
GQUIC_CERT_PATH=/path/to/cert.pem
GQUIC_KEY_PATH=/path/to/key.pem
```

## FFI Integration

For Zig integration, see the [INTEGRATION.md](INTEGRATION.md) guide.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass: `cargo test`
5. Check formatting: `cargo fmt`
6. Run clippy: `cargo clippy`
7. Submit a pull request

## License

MIT © 2025 GhostKellz