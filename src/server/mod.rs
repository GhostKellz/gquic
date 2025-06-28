use anyhow::Result;
use quinn::{Endpoint, Incoming, NewConnection, ServerConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

pub mod builder;
pub mod config;
pub mod handler;

pub use builder::QuicServerBuilder;
pub use config::QuicServerConfig;
pub use handler::{ConnectionHandler, DefaultHandler};

#[derive(Debug)]
pub struct QuicServer {
    endpoint: Endpoint,
    config: Arc<QuicServerConfig>,
    handler: Arc<dyn ConnectionHandler>,
}

impl QuicServer {
    pub fn builder() -> QuicServerBuilder {
        QuicServerBuilder::new()
    }

    pub fn new(config: QuicServerConfig) -> Result<Self> {
        Self::new_with_handler(config, Arc::new(DefaultHandler))
    }

    pub fn new_with_handler(
        config: QuicServerConfig,
        handler: Arc<dyn ConnectionHandler>,
    ) -> Result<Self> {
        let server_config = Self::build_quinn_config(&config)?;
        let endpoint = Endpoint::server(server_config, config.bind_addr)?;

        Ok(Self {
            endpoint,
            config: Arc::new(config),
            handler,
        })
    }

    pub async fn run(self) -> Result<()> {
        info!("🚀 QUIC server starting on {}", self.config.bind_addr);
        
        while let Some(conn) = self.endpoint.accept().await {
            let handler = Arc::clone(&self.handler);
            let config = Arc::clone(&self.config);
            
            tokio::spawn(async move {
                if let Err(e) = Self::handle_connection(conn, handler, config).await {
                    error!("Connection error: {}", e);
                }
            });
        }

        Ok(())
    }

    pub fn config(&self) -> &QuicServerConfig {
        &self.config
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.endpoint.local_addr()?)
    }

    async fn handle_connection(
        connecting: Incoming,
        handler: Arc<dyn ConnectionHandler>,
        config: Arc<QuicServerConfig>,
    ) -> Result<()> {
        let connection = connecting.await?;
        let remote_addr = connection.connection.remote_address();
        
        info!("🔗 New connection from {}", remote_addr);
        debug!("Connection info: {:?}", connection.connection.stats());

        match handler.handle_connection(connection, config).await {
            Ok(_) => {
                info!("✅ Connection from {} completed successfully", remote_addr);
            }
            Err(e) => {
                error!("❌ Connection from {} failed: {}", remote_addr, e);
            }
        }

        Ok(())
    }

    fn build_quinn_config(config: &QuicServerConfig) -> Result<ServerConfig> {
        let mut server_config = ServerConfig::with_crypto(Arc::new(config.tls_config.clone()));
        
        server_config.transport = Arc::new(config.transport_config.clone());
        
        Ok(server_config)
    }
}