use super::{QuicClient, QuicClientConfig};
use anyhow::Result;

pub struct QuicClientBuilder {
    config: QuicClientConfig,
}

impl QuicClientBuilder {
    pub fn new() -> Self {
        Self {
            config: QuicClientConfig::default(),
        }
    }

    pub fn server_name(mut self, name: String) -> Self {
        self.config.server_name = name;
        self
    }

    pub fn with_alpn(mut self, protocol: &str) -> Self {
        self.config.alpn_protocols.push(protocol.as_bytes().to_vec());
        self
    }

    pub fn max_idle_timeout(mut self, timeout_ms: u64) -> Self {
        self.config.max_idle_timeout = Some(timeout_ms);
        self
    }

    pub fn max_bi_streams(mut self, count: u32) -> Self {
        self.config.max_bi_streams = Some(count);
        self
    }

    pub fn max_uni_streams(mut self, count: u32) -> Self {
        self.config.max_uni_streams = Some(count);
        self
    }

    pub fn keep_alive_interval(mut self, interval_ms: u64) -> Self {
        self.config.keep_alive_interval = Some(interval_ms);
        self
    }

    pub fn enable_0rtt(mut self, enable: bool) -> Self {
        self.config.enable_0rtt = enable;
        self
    }

    pub fn enable_migration(mut self, enable: bool) -> Self {
        self.config.enable_migration = enable;
        self
    }

    pub fn build(self) -> QuicClientConfig {
        self.config
    }

    pub fn build_client(self) -> Result<QuicClient> {
        let config = self.build();
        QuicClient::new(config)
    }
}

impl Default for QuicClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}