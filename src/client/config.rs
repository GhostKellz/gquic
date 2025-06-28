use std::time::Duration;

/// QUIC client configuration
#[derive(Debug, Clone)]
pub struct QuicClientConfig {
    pub server_name: String,
    pub alpn_protocols: Vec<Vec<u8>>,
    pub max_idle_timeout: Option<u64>,
    pub max_bi_streams: Option<u32>,
    pub max_uni_streams: Option<u32>,
    pub keep_alive_interval: Option<u64>,
    pub enable_0rtt: bool,
    pub enable_migration: bool,
}

impl Default for QuicClientConfig {
    fn default() -> Self {
        Self {
            server_name: "localhost".to_string(),
            alpn_protocols: vec![b"gquic".to_vec()],
            max_idle_timeout: Some(30_000), // 30 seconds in milliseconds
            max_bi_streams: Some(100),
            max_uni_streams: Some(100),
            keep_alive_interval: Some(10_000), // 10 seconds in milliseconds
            enable_0rtt: true,
            enable_migration: false, // Disabled by default for security
        }
    }
}

impl QuicClientConfig {
    /// Create a new configuration builder
    pub fn builder() -> QuicClientConfigBuilder {
        QuicClientConfigBuilder::new()
    }
}

/// Builder for QuicClientConfig
#[derive(Debug)]
pub struct QuicClientConfigBuilder {
    config: QuicClientConfig,
}

impl QuicClientConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: QuicClientConfig::default(),
        }
    }

    /// Set the server name for SNI
    pub fn server_name(mut self, name: String) -> Self {
        self.config.server_name = name;
        self
    }

    /// Add an ALPN protocol
    pub fn with_alpn(mut self, protocol: &str) -> Self {
        self.config.alpn_protocols.push(protocol.as_bytes().to_vec());
        self
    }

    /// Set ALPN protocols
    pub fn alpn_protocols(mut self, protocols: Vec<Vec<u8>>) -> Self {
        self.config.alpn_protocols = protocols;
        self
    }

    /// Set maximum idle timeout in milliseconds
    pub fn max_idle_timeout(mut self, timeout_ms: u64) -> Self {
        self.config.max_idle_timeout = Some(timeout_ms);
        self
    }

    /// Set maximum number of bidirectional streams
    pub fn max_bi_streams(mut self, count: u32) -> Self {
        self.config.max_bi_streams = Some(count);
        self
    }

    /// Set maximum number of unidirectional streams
    pub fn max_uni_streams(mut self, count: u32) -> Self {
        self.config.max_uni_streams = Some(count);
        self
    }

    /// Set keep-alive interval in milliseconds
    pub fn keep_alive_interval(mut self, interval_ms: u64) -> Self {
        self.config.keep_alive_interval = Some(interval_ms);
        self
    }

    /// Enable or disable 0-RTT
    pub fn enable_0rtt(mut self, enable: bool) -> Self {
        self.config.enable_0rtt = enable;
        self
    }

    /// Enable or disable connection migration
    pub fn enable_migration(mut self, enable: bool) -> Self {
        self.config.enable_migration = enable;
        self
    }

    /// Build the configuration
    pub fn build(self) -> QuicClientConfig {
        self.config
    }

    /// Build a QuicClient with this configuration
    pub fn build_client(self) -> anyhow::Result<crate::client::QuicClient> {
        let config = self.build();
        crate::client::QuicClient::new(config)
    }
}

impl Default for QuicClientConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}