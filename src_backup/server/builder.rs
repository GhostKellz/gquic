use super::{QuicServer, QuicServerConfig};
use crate::server::handler::{ConnectionHandler, DefaultHandler};
use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

pub struct QuicServerBuilder {
    config_builder: QuicServerConfigBuilder,
    handler: Option<Arc<dyn ConnectionHandler>>,
}

impl QuicServerBuilder {
    pub fn new() -> Self {
        Self {
            config_builder: QuicServerConfig::builder(),
            handler: None,
        }
    }

    pub fn bind(mut self, addr: SocketAddr) -> Self {
        self.config_builder = self.config_builder.bind(addr);
        self
    }

    pub fn with_tls_files(mut self, cert_path: &str, key_path: &str) -> Result<Self> {
        self.config_builder = self.config_builder.with_tls_files(cert_path, key_path)?;
        Ok(self)
    }

    pub fn with_self_signed_cert(mut self) -> Result<Self> {
        self.config_builder = self.config_builder.with_self_signed_cert()?;
        Ok(self)
    }

    pub fn with_alpn(mut self, protocol: &str) -> Self {
        self.config_builder = self.config_builder.with_alpn(protocol);
        self
    }

    pub fn with_handler(mut self, handler: Arc<dyn ConnectionHandler>) -> Self {
        self.handler = Some(handler);
        self
    }

    pub fn max_concurrent_bidi_streams(mut self, count: u32) -> Self {
        self.config_builder = self.config_builder.max_concurrent_bidi_streams(count);
        self
    }

    pub fn max_concurrent_uni_streams(mut self, count: u32) -> Self {
        self.config_builder = self.config_builder.max_concurrent_uni_streams(count);
        self
    }

    pub fn max_idle_timeout(mut self, timeout: Duration) -> Self {
        self.config_builder = self.config_builder.max_idle_timeout(timeout.as_millis() as u64);
        self
    }

    pub fn keep_alive_interval(mut self, interval: Duration) -> Self {
        self.config_builder = self.config_builder.keep_alive_interval(interval.as_millis() as u64);
        self
    }

    pub fn build(self) -> Result<QuicServer> {
        let config = self.config_builder.build()?;
        let handler = self.handler.unwrap_or_else(|| Arc::new(DefaultHandler));
        
        QuicServer::new_with_handler(config, handler)
    }
}

impl Default for QuicServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// Re-export the config builder for convenience
pub use super::config::QuicServerConfigBuilder;