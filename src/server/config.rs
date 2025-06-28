use anyhow::Result;
use std::fs;
use std::net::SocketAddr;
use std::time::Duration;

/// QUIC server configuration
#[derive(Debug)]
pub struct QuicServerConfig {
    pub bind_addr: SocketAddr,
    pub alpn_protocols: Vec<Vec<u8>>,
    pub max_concurrent_connections: Option<usize>,
    pub max_idle_timeout: Option<u64>, // milliseconds
    pub keep_alive_interval: Option<u64>, // milliseconds
    pub max_concurrent_bidi_streams: Option<u32>,
    pub max_concurrent_uni_streams: Option<u32>,
    pub enable_0rtt: bool,
    pub enable_migration: bool,
    // TLS configuration will be handled by gcrypt in the future
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub use_self_signed: bool,
}

impl QuicServerConfig {
    /// Create a new configuration builder
    pub fn builder() -> QuicServerConfigBuilder {
        QuicServerConfigBuilder::new()
    }
}

/// Builder for QuicServerConfig
#[derive(Debug)]
pub struct QuicServerConfigBuilder {
    bind_addr: Option<SocketAddr>,
    cert_path: Option<String>,
    key_path: Option<String>,
    alpn_protocols: Vec<Vec<u8>>,
    max_concurrent_connections: Option<usize>,
    max_idle_timeout: Option<u64>,
    keep_alive_interval: Option<u64>,
    max_concurrent_bidi_streams: Option<u32>,
    max_concurrent_uni_streams: Option<u32>,
    enable_0rtt: bool,
    enable_migration: bool,
    use_self_signed: bool,
}

impl QuicServerConfigBuilder {
    pub fn new() -> Self {
        Self {
            bind_addr: None,
            cert_path: None,
            key_path: None,
            alpn_protocols: vec![b"gquic".to_vec()],
            max_concurrent_connections: Some(1000),
            max_idle_timeout: Some(30_000), // 30 seconds
            keep_alive_interval: Some(10_000), // 10 seconds
            max_concurrent_bidi_streams: Some(100),
            max_concurrent_uni_streams: Some(100),
            enable_0rtt: true,
            enable_migration: false,
            use_self_signed: false,
        }
    }

    /// Set the bind address
    pub fn bind(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = Some(addr);
        self
    }

    /// Set TLS certificate and key files
    pub fn with_tls_files(mut self, cert_path: &str, key_path: &str) -> Result<Self> {
        // Validate that files exist
        if !std::path::Path::new(cert_path).exists() {
            return Err(anyhow::anyhow!("Certificate file not found: {}", cert_path));
        }
        if !std::path::Path::new(key_path).exists() {
            return Err(anyhow::anyhow!("Private key file not found: {}", key_path));
        }
        
        self.cert_path = Some(cert_path.to_string());
        self.key_path = Some(key_path.to_string());
        Ok(self)
    }

    /// Use a self-signed certificate (development only)
    pub fn with_self_signed_cert(mut self) -> Result<Self> {
        self.use_self_signed = true;
        Ok(self)
    }

    /// Add an ALPN protocol
    pub fn with_alpn(mut self, protocol: &str) -> Self {
        self.alpn_protocols.push(protocol.as_bytes().to_vec());
        self
    }

    /// Set ALPN protocols
    pub fn alpn_protocols(mut self, protocols: Vec<Vec<u8>>) -> Self {
        self.alpn_protocols = protocols;
        self
    }

    /// Set maximum concurrent connections
    pub fn max_concurrent_connections(mut self, count: usize) -> Self {
        self.max_concurrent_connections = Some(count);
        self
    }

    /// Set maximum concurrent bidirectional streams
    pub fn max_concurrent_bidi_streams(mut self, count: u32) -> Self {
        self.max_concurrent_bidi_streams = Some(count);
        self
    }

    /// Set maximum concurrent unidirectional streams
    pub fn max_concurrent_uni_streams(mut self, count: u32) -> Self {
        self.max_concurrent_uni_streams = Some(count);
        self
    }

    /// Set maximum idle timeout in milliseconds
    pub fn max_idle_timeout(mut self, timeout_ms: u64) -> Self {
        self.max_idle_timeout = Some(timeout_ms);
        self
    }

    /// Set keep-alive interval in milliseconds
    pub fn keep_alive_interval(mut self, interval_ms: u64) -> Self {
        self.keep_alive_interval = Some(interval_ms);
        self
    }

    /// Enable or disable 0-RTT
    pub fn enable_0rtt(mut self, enable: bool) -> Self {
        self.enable_0rtt = enable;
        self
    }

    /// Enable or disable connection migration
    pub fn enable_migration(mut self, enable: bool) -> Self {
        self.enable_migration = enable;
        self
    }

    /// Set a custom connection handler
    pub fn with_handler(self, handler: std::sync::Arc<dyn crate::server::ConnectionHandler>) -> QuicServerBuilderWithHandler {
        QuicServerBuilderWithHandler {
            config_builder: self,
            handler,
        }
    }

    /// Build the configuration
    pub fn build(self) -> Result<QuicServerConfig> {
        let bind_addr = self.bind_addr.unwrap_or_else(|| "0.0.0.0:443".parse().unwrap());
        
        if !self.use_self_signed && self.cert_path.is_none() {
            return Err(anyhow::anyhow!("TLS certificate required (use with_tls_files or with_self_signed_cert)"));
        }

        Ok(QuicServerConfig {
            bind_addr,
            alpn_protocols: self.alpn_protocols,
            max_concurrent_connections: self.max_concurrent_connections,
            max_idle_timeout: self.max_idle_timeout,
            keep_alive_interval: self.keep_alive_interval,
            max_concurrent_bidi_streams: self.max_concurrent_bidi_streams,
            max_concurrent_uni_streams: self.max_concurrent_uni_streams,
            enable_0rtt: self.enable_0rtt,
            enable_migration: self.enable_migration,
            cert_path: self.cert_path,
            key_path: self.key_path,
            use_self_signed: self.use_self_signed,
        })
    }

    /// Build a QuicServer with this configuration
    pub fn build_server(self) -> Result<crate::server::QuicServer> {
        let config = self.build()?;
        crate::server::QuicServer::new(config)
    }
}

/// Builder with handler attached
pub struct QuicServerBuilderWithHandler {
    config_builder: QuicServerConfigBuilder,
    handler: std::sync::Arc<dyn crate::server::ConnectionHandler>,
}

impl QuicServerBuilderWithHandler {
    /// Build a QuicServer with the handler
    pub fn build(self) -> Result<crate::server::QuicServer> {
        let config = self.config_builder.build()?;
        crate::server::QuicServer::new_with_handler(config, self.handler)
    }
}

impl Default for QuicServerConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// Helper functions for certificate generation (will be replaced with gcrypt)
pub fn generate_self_signed_cert() -> Result<(Vec<u8>, Vec<u8>)> {
    // For now, return empty data - this will be implemented with gcrypt
    // In the meantime, applications should use proper certificates
    Err(anyhow::anyhow!("Self-signed certificate generation not yet implemented with gcrypt"))
}

pub fn load_cert_file(path: &str) -> Result<Vec<u8>> {
    fs::read(path).map_err(|e| anyhow::anyhow!("Failed to read certificate file {}: {}", path, e))
}

pub fn load_key_file(path: &str) -> Result<Vec<u8>> {
    fs::read(path).map_err(|e| anyhow::anyhow!("Failed to read private key file {}: {}", path, e))
}