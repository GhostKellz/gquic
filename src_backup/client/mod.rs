use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

use crate::quic::{Endpoint, EndpointConfig, Connection, BiStream, UniStream};

pub mod builder;
pub mod config;
pub mod stream;

pub use builder::QuicClientBuilder;
pub use config::QuicClientConfig;
pub use stream::{ClientBiStream, ClientUniStream};

/// QUIC client using our custom implementation
#[derive(Debug)]
pub struct QuicClient {
    endpoint: Endpoint,
    config: QuicClientConfig,
}

impl QuicClient {
    /// Create a new client builder
    pub fn builder() -> QuicClientBuilder {
        QuicClientBuilder::new()
    }

    /// Create a new QUIC client with the given configuration
    pub fn new(config: QuicClientConfig) -> Result<Self> {
        // Use a random local port for client
        let bind_addr = "0.0.0.0:0".parse()?;
        
        let mut endpoint_config = EndpointConfig::default();
        endpoint_config.alpn_protocols = config.alpn_protocols.iter()
            .map(|p| String::from_utf8_lossy(p).to_string())
            .collect();
        endpoint_config.idle_timeout = std::time::Duration::from_millis(config.max_idle_timeout.unwrap_or(30000));
        
        // Create client endpoint (this will be async in real implementation)
        let endpoint = tokio::runtime::Handle::current().block_on(async {
            Endpoint::client(bind_addr).await
        })?;

        Ok(Self { endpoint, config })
    }

    /// Connect to a remote server
    pub async fn connect(&self, addr: SocketAddr) -> Result<Connection> {
        let connection = self.endpoint.connect(addr, &self.config.server_name).await?;
        
        info!("Connected to {} ({})", addr, self.config.server_name);
        Ok(connection)
    }

    /// Connect with a specific ALPN protocol
    pub async fn connect_with_alpn(&self, addr: SocketAddr, alpn: &str) -> Result<Connection> {
        // For now, use the same connect method
        // In a full implementation, we'd modify the endpoint config for this specific connection
        let connection = self.connect(addr).await?;
        debug!("Connected with ALPN: {}", alpn);
        Ok(connection)
    }

    /// Open a bidirectional stream on the given connection
    pub async fn open_bi_stream(&self, conn: &Connection) -> Result<BiStream> {
        let stream = conn.open_bi().await?;
        Ok(stream)
    }

    /// Open a unidirectional stream on the given connection
    pub async fn open_uni_stream(&self, conn: &Connection) -> Result<UniStream> {
        let stream = conn.open_uni().await?;
        Ok(stream)
    }

    /// Get the local endpoint address
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint.local_addr().map_err(|e| anyhow::anyhow!("Endpoint local_addr error: {}", e))
    }

    /// Get client configuration
    pub fn config(&self) -> &QuicClientConfig {
        &self.config
    }

    /// Close the client and all its connections
    pub async fn close(&self) -> Result<()> {
        self.endpoint.close().await.map_err(|e| anyhow::anyhow!("Endpoint close error: {}", e))
    }
}