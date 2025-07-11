//! Configuration management for QUIC connections and servers
//! 
//! This module provides comprehensive configuration management for QUIC
//! connections, servers, and various protocol features.

use crate::quic::error::{QuicError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tracing::Level;

/// Main QUIC configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicConfig {
    /// Connection configuration
    pub connection: ConnectionConfig,
    /// Server configuration
    pub server: ServerConfig,
    /// TLS configuration
    pub tls: TlsConfig,
    /// HTTP/3 configuration
    pub http3: Http3Config,
    /// gRPC configuration
    pub grpc: GrpcConfig,
    /// Crypto configuration
    pub crypto: CryptoConfig,
    /// Logging configuration
    pub logging: LoggingConfig,
    /// Performance configuration
    pub performance: PerformanceConfig,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            connection: ConnectionConfig::default(),
            server: ServerConfig::default(),
            tls: TlsConfig::default(),
            http3: Http3Config::default(),
            grpc: GrpcConfig::default(),
            crypto: CryptoConfig::default(),
            logging: LoggingConfig::default(),
            performance: PerformanceConfig::default(),
        }
    }
}

/// Connection-level configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionConfig {
    /// Maximum idle timeout in milliseconds
    pub max_idle_timeout: u64,
    /// Keep-alive interval in milliseconds
    pub keep_alive_interval: u64,
    /// Maximum number of bidirectional streams
    pub max_bi_streams: u64,
    /// Maximum number of unidirectional streams
    pub max_uni_streams: u64,
    /// Initial flow control window size
    pub initial_max_data: u64,
    /// Initial stream flow control window size
    pub initial_max_stream_data: u64,
    /// Maximum UDP payload size
    pub max_udp_payload_size: u64,
    /// Connection migration enabled
    pub migration_enabled: bool,
    /// 0-RTT enabled
    pub zero_rtt_enabled: bool,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            max_idle_timeout: 30_000,      // 30 seconds
            keep_alive_interval: 10_000,   // 10 seconds
            max_bi_streams: 100,
            max_uni_streams: 100,
            initial_max_data: 1024 * 1024, // 1MB
            initial_max_stream_data: 256 * 1024, // 256KB
            max_udp_payload_size: 1452,    // Common MTU size
            migration_enabled: true,
            zero_rtt_enabled: false,
        }
    }
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Bind address
    pub bind_address: SocketAddr,
    /// Alternative bind addresses
    pub alt_addresses: Vec<SocketAddr>,
    /// Maximum concurrent connections
    pub max_connections: u64,
    /// Connection backlog size
    pub backlog_size: u32,
    /// Enable connection pooling
    pub connection_pooling: bool,
    /// Worker thread count
    pub worker_threads: usize,
    /// Enable graceful shutdown
    pub graceful_shutdown: bool,
    /// Shutdown timeout in seconds
    pub shutdown_timeout: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0:443".parse().unwrap(),
            alt_addresses: Vec::new(),
            max_connections: 10_000,
            backlog_size: 1024,
            connection_pooling: true,
            worker_threads: num_cpus::get(),
            graceful_shutdown: true,
            shutdown_timeout: 30,
        }
    }
}

/// TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Certificate chain file path
    pub cert_chain: Option<PathBuf>,
    /// Private key file path
    pub private_key: Option<PathBuf>,
    /// CA certificate file path
    pub ca_cert: Option<PathBuf>,
    /// ALPN protocols
    pub alpn_protocols: Vec<String>,
    /// Verify peer certificates
    pub verify_peer: bool,
    /// Enable session resumption
    pub session_resumption: bool,
    /// Cipher suites
    pub cipher_suites: Vec<String>,
    /// Minimum TLS version
    pub min_version: String,
    /// Maximum TLS version
    pub max_version: String,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            cert_chain: None,
            private_key: None,
            ca_cert: None,
            alpn_protocols: vec![
                "h3".to_string(),
                "grpc".to_string(),
            ],
            verify_peer: true,
            session_resumption: true,
            cipher_suites: vec![
                "TLS_AES_256_GCM_SHA384".to_string(),
                "TLS_AES_128_GCM_SHA256".to_string(),
                "TLS_CHACHA20_POLY1305_SHA256".to_string(),
            ],
            min_version: "1.3".to_string(),
            max_version: "1.3".to_string(),
        }
    }
}

/// HTTP/3 configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Http3Config {
    /// Enable HTTP/3 support
    pub enabled: bool,
    /// Maximum field section size
    pub max_field_section_size: u64,
    /// QPACK max table capacity
    pub qpack_max_table_capacity: u64,
    /// QPACK blocked streams
    pub qpack_blocked_streams: u64,
    /// Enable server push
    pub server_push_enabled: bool,
    /// Maximum push streams
    pub max_push_streams: u64,
    /// Request timeout in seconds
    pub request_timeout: u64,
    /// Response timeout in seconds
    pub response_timeout: u64,
}

impl Default for Http3Config {
    fn default() -> Self {
        Self {
            enabled: true,
            max_field_section_size: 16384,    // 16KB
            qpack_max_table_capacity: 4096,   // 4KB
            qpack_blocked_streams: 100,
            server_push_enabled: false,
            max_push_streams: 0,
            request_timeout: 60,
            response_timeout: 60,
        }
    }
}

/// gRPC configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrpcConfig {
    /// Enable gRPC-over-QUIC support
    pub enabled: bool,
    /// Maximum message size
    pub max_message_size: u64,
    /// Maximum concurrent streams per connection
    pub max_concurrent_streams: u64,
    /// Enable gRPC reflection
    pub reflection_enabled: bool,
    /// gRPC timeout in seconds
    pub timeout: u64,
    /// Keep-alive time in seconds
    pub keep_alive_time: u64,
    /// Keep-alive timeout in seconds
    pub keep_alive_timeout: u64,
    /// Enable gRPC-Web support
    pub web_enabled: bool,
    /// Compression algorithms
    pub compression: Vec<String>,
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_message_size: 16 * 1024 * 1024, // 16MB
            max_concurrent_streams: 1000,
            reflection_enabled: false,
            timeout: 60,
            keep_alive_time: 30,
            keep_alive_timeout: 10,
            web_enabled: false,
            compression: vec![
                "gzip".to_string(),
                "deflate".to_string(),
            ],
        }
    }
}

/// Crypto configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConfig {
    /// Crypto backend to use
    pub backend: CryptoBackend,
    /// Enable hardware acceleration
    pub hardware_acceleration: bool,
    /// Key rotation interval in seconds
    pub key_rotation_interval: u64,
    /// Enable perfect forward secrecy
    pub perfect_forward_secrecy: bool,
    /// Supported curve algorithms
    pub curves: Vec<String>,
    /// Supported signature algorithms
    pub signature_algorithms: Vec<String>,
}

/// Crypto backend selection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CryptoBackend {
    /// GCC (GhostChain Crypto) - default
    Gcc,
    /// Ring crypto library
    Ring,
    /// RustLS crypto
    RustLS,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            backend: CryptoBackend::Gcc,
            hardware_acceleration: true,
            key_rotation_interval: 3600, // 1 hour
            perfect_forward_secrecy: true,
            curves: vec![
                "x25519".to_string(),
                "secp256r1".to_string(),
                "secp384r1".to_string(),
            ],
            signature_algorithms: vec![
                "ed25519".to_string(),
                "rsa_pss_rsae_sha256".to_string(),
                "ecdsa_secp256r1_sha256".to_string(),
            ],
        }
    }
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level
    pub level: String,
    /// Log format
    pub format: LogFormat,
    /// Log output
    pub output: LogOutput,
    /// Enable structured logging
    pub structured: bool,
    /// Log file path
    pub file_path: Option<PathBuf>,
    /// Log file rotation
    pub rotation: LogRotation,
    /// Enable tracing
    pub tracing_enabled: bool,
    /// Tracing endpoint
    pub tracing_endpoint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogFormat {
    Text,
    Json,
    Compact,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogOutput {
    Stdout,
    Stderr,
    File,
    Syslog,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRotation {
    /// Enable rotation
    pub enabled: bool,
    /// Max file size in bytes
    pub max_size: u64,
    /// Max number of files
    pub max_files: u32,
    /// Compress rotated files
    pub compress: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: LogFormat::Text,
            output: LogOutput::Stdout,
            structured: true,
            file_path: None,
            rotation: LogRotation {
                enabled: true,
                max_size: 100 * 1024 * 1024, // 100MB
                max_files: 10,
                compress: true,
            },
            tracing_enabled: false,
            tracing_endpoint: None,
        }
    }
}

/// Performance configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Enable performance monitoring
    pub monitoring_enabled: bool,
    /// Metrics collection interval in seconds
    pub metrics_interval: u64,
    /// Enable connection pooling
    pub connection_pooling: bool,
    /// Pool size
    pub pool_size: u32,
    /// Pool timeout in seconds
    pub pool_timeout: u64,
    /// Buffer sizes
    pub buffer_sizes: BufferSizes,
    /// Congestion control algorithm
    pub congestion_control: String,
    /// Enable bandwidth estimation
    pub bandwidth_estimation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BufferSizes {
    /// Send buffer size
    pub send_buffer: u32,
    /// Receive buffer size
    pub receive_buffer: u32,
    /// Socket buffer size
    pub socket_buffer: u32,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            monitoring_enabled: true,
            metrics_interval: 30,
            connection_pooling: true,
            pool_size: 100,
            pool_timeout: 30,
            buffer_sizes: BufferSizes {
                send_buffer: 1024 * 1024,     // 1MB
                receive_buffer: 1024 * 1024,  // 1MB
                socket_buffer: 2 * 1024 * 1024, // 2MB
            },
            congestion_control: "cubic".to_string(),
            bandwidth_estimation: true,
        }
    }
}

impl QuicConfig {
    /// Load configuration from file
    pub fn load_from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| QuicError::Config(format!("Failed to read config file: {}", e)))?;
        
        // Try different formats
        if let Ok(config) = toml::from_str::<Self>(&contents) {
            return Ok(config);
        }
        
        if let Ok(config) = serde_json::from_str::<Self>(&contents) {
            return Ok(config);
        }
        
        if let Ok(config) = serde_yaml::from_str::<Self>(&contents) {
            return Ok(config);
        }
        
        Err(QuicError::Config("Unsupported config format".to_string()))
    }
    
    /// Save configuration to file
    pub fn save_to_file<P: AsRef<std::path::Path>>(&self, path: P, format: ConfigFormat) -> Result<()> {
        let contents = match format {
            ConfigFormat::Toml => toml::to_string_pretty(self)
                .map_err(|e| QuicError::Config(format!("Failed to serialize to TOML: {}", e)))?,
            ConfigFormat::Json => serde_json::to_string_pretty(self)
                .map_err(|e| QuicError::Config(format!("Failed to serialize to JSON: {}", e)))?,
            ConfigFormat::Yaml => serde_yaml::to_string(self)
                .map_err(|e| QuicError::Config(format!("Failed to serialize to YAML: {}", e)))?,
        };
        
        std::fs::write(path, contents)
            .map_err(|e| QuicError::Config(format!("Failed to write config file: {}", e)))?;
        
        Ok(())
    }
    
    /// Load configuration from environment variables
    pub fn load_from_env() -> Result<Self> {
        let mut config = Self::default();
        
        // Connection config
        if let Ok(val) = std::env::var("QUIC_MAX_IDLE_TIMEOUT") {
            config.connection.max_idle_timeout = val.parse()
                .map_err(|e| QuicError::Config(format!("Invalid QUIC_MAX_IDLE_TIMEOUT: {}", e)))?;
        }
        
        if let Ok(val) = std::env::var("QUIC_MAX_BI_STREAMS") {
            config.connection.max_bi_streams = val.parse()
                .map_err(|e| QuicError::Config(format!("Invalid QUIC_MAX_BI_STREAMS: {}", e)))?;
        }
        
        // Server config
        if let Ok(val) = std::env::var("QUIC_BIND_ADDRESS") {
            config.server.bind_address = val.parse()
                .map_err(|e| QuicError::Config(format!("Invalid QUIC_BIND_ADDRESS: {}", e)))?;
        }
        
        if let Ok(val) = std::env::var("QUIC_MAX_CONNECTIONS") {
            config.server.max_connections = val.parse()
                .map_err(|e| QuicError::Config(format!("Invalid QUIC_MAX_CONNECTIONS: {}", e)))?;
        }
        
        // TLS config
        if let Ok(val) = std::env::var("QUIC_CERT_CHAIN") {
            config.tls.cert_chain = Some(PathBuf::from(val));
        }
        
        if let Ok(val) = std::env::var("QUIC_PRIVATE_KEY") {
            config.tls.private_key = Some(PathBuf::from(val));
        }
        
        // Logging config
        if let Ok(val) = std::env::var("QUIC_LOG_LEVEL") {
            config.logging.level = val;
        }
        
        Ok(config)
    }
    
    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        // Validate connection config
        if self.connection.max_idle_timeout == 0 {
            return Err(QuicError::Config("max_idle_timeout must be greater than 0".to_string()));
        }
        
        if self.connection.max_bi_streams == 0 {
            return Err(QuicError::Config("max_bi_streams must be greater than 0".to_string()));
        }
        
        // Validate server config
        if self.server.max_connections == 0 {
            return Err(QuicError::Config("max_connections must be greater than 0".to_string()));
        }
        
        // Validate TLS config
        if self.tls.alpn_protocols.is_empty() {
            return Err(QuicError::Config("At least one ALPN protocol must be specified".to_string()));
        }
        
        // Validate gRPC config
        if self.grpc.enabled && self.grpc.max_message_size == 0 {
            return Err(QuicError::Config("gRPC max_message_size must be greater than 0".to_string()));
        }
        
        Ok(())
    }
    
    /// Get duration values
    pub fn idle_timeout(&self) -> Duration {
        Duration::from_millis(self.connection.max_idle_timeout)
    }
    
    pub fn keep_alive_interval(&self) -> Duration {
        Duration::from_millis(self.connection.keep_alive_interval)
    }
    
    pub fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(self.server.shutdown_timeout)
    }
    
    /// Get tracing level
    pub fn tracing_level(&self) -> Level {
        match self.logging.level.to_lowercase().as_str() {
            "trace" => Level::TRACE,
            "debug" => Level::DEBUG,
            "info" => Level::INFO,
            "warn" => Level::WARN,
            "error" => Level::ERROR,
            _ => Level::INFO,
        }
    }
}

/// Configuration file format
#[derive(Debug, Clone, Copy)]
pub enum ConfigFormat {
    Toml,
    Json,
    Yaml,
}

/// Configuration builder for easier setup
pub struct ConfigBuilder {
    config: QuicConfig,
}

impl ConfigBuilder {
    /// Create a new configuration builder
    pub fn new() -> Self {
        Self {
            config: QuicConfig::default(),
        }
    }
    
    /// Set bind address
    pub fn bind_address(mut self, addr: SocketAddr) -> Self {
        self.config.server.bind_address = addr;
        self
    }
    
    /// Set maximum connections
    pub fn max_connections(mut self, max: u64) -> Self {
        self.config.server.max_connections = max;
        self
    }
    
    /// Set TLS certificate chain
    pub fn cert_chain<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.config.tls.cert_chain = Some(path.into());
        self
    }
    
    /// Set TLS private key
    pub fn private_key<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.config.tls.private_key = Some(path.into());
        self
    }
    
    /// Add ALPN protocol
    pub fn alpn_protocol<S: Into<String>>(mut self, protocol: S) -> Self {
        self.config.tls.alpn_protocols.push(protocol.into());
        self
    }
    
    /// Enable gRPC support
    pub fn enable_grpc(mut self) -> Self {
        self.config.grpc.enabled = true;
        self
    }
    
    /// Set crypto backend
    pub fn crypto_backend(mut self, backend: CryptoBackend) -> Self {
        self.config.crypto.backend = backend;
        self
    }
    
    /// Set log level
    pub fn log_level<S: Into<String>>(mut self, level: S) -> Self {
        self.config.logging.level = level.into();
        self
    }
    
    /// Build the configuration
    pub fn build(self) -> Result<QuicConfig> {
        self.config.validate()?;
        Ok(self.config)
    }
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// Add required dependencies to Cargo.toml
// toml = "0.8"
// serde_json = "1.0"
// serde_yaml = "0.9"
// num_cpus = "1.0"

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_config() {
        let config = QuicConfig::default();
        assert!(config.validate().is_ok());
    }
    
    #[test]
    fn test_config_builder() {
        let config = ConfigBuilder::new()
            .bind_address("127.0.0.1:8080".parse().unwrap())
            .max_connections(1000)
            .enable_grpc()
            .log_level("debug")
            .build()
            .unwrap();
        
        assert_eq!(config.server.bind_address.to_string(), "127.0.0.1:8080");
        assert_eq!(config.server.max_connections, 1000);
        assert!(config.grpc.enabled);
        assert_eq!(config.logging.level, "debug");
    }
    
    #[test]
    fn test_config_validation() {
        let mut config = QuicConfig::default();
        config.connection.max_idle_timeout = 0;
        
        assert!(config.validate().is_err());
    }
}