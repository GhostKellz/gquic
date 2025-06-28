use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

use crate::quic::{Endpoint, EndpointConfig, Connection, EndpointEvent};

pub mod builder;
pub mod config;
pub mod handler;

pub use builder::QuicServerBuilder;
pub use config::QuicServerConfig;
pub use handler::{ConnectionHandler, DefaultHandler};

/// QUIC server using our custom implementation
pub struct QuicServer {
    endpoint: Endpoint,
    config: Arc<QuicServerConfig>,
    handler: Arc<dyn ConnectionHandler>,
}

impl QuicServer {
    /// Create a new server builder
    pub fn builder() -> QuicServerBuilder {
        QuicServerBuilder::new()
    }

    /// Create a new QUIC server with the given configuration
    pub fn new(config: QuicServerConfig) -> Result<Self> {
        Self::new_with_handler(config, Arc::new(DefaultHandler))
    }

    /// Create a new QUIC server with a custom connection handler
    pub fn new_with_handler(
        config: QuicServerConfig,
        handler: Arc<dyn ConnectionHandler>,
    ) -> Result<Self> {
        let mut endpoint_config = EndpointConfig::default();
        endpoint_config.alpn_protocols = config.alpn_protocols.iter()
            .map(|p| String::from_utf8_lossy(p).to_string())
            .collect();
        endpoint_config.max_concurrent_connections = config.max_concurrent_connections.unwrap_or(1000);
        endpoint_config.idle_timeout = std::time::Duration::from_millis(config.max_idle_timeout.unwrap_or(30000));
        endpoint_config.keep_alive_interval = std::time::Duration::from_millis(config.keep_alive_interval.unwrap_or(10000));

        // Create server endpoint (this will be async in real implementation)
        let endpoint = tokio::runtime::Handle::current().block_on(async {
            Endpoint::server(config.bind_addr, endpoint_config).await
        })?;

        Ok(Self {
            endpoint,
            config: Arc::new(config),
            handler,
        })
    }

    /// Get server configuration
    pub fn config(&self) -> &QuicServerConfig {
        &self.config
    }

    /// Get the local endpoint address
    pub fn local_addr(&self) -> Result<SocketAddr> {
        // For now, return the configured bind address
        Ok(self.config.bind_addr)
    }

    /// Run the server's main event loop
    pub async fn run(self) -> Result<()> {
        info!("🚀 QUIC server starting on {}", self.config.bind_addr);
        info!("📡 ALPN protocols: {:?}", self.config.alpn_protocols);

        // Extract fields to avoid borrowing issues
        let endpoint = Arc::new(self.endpoint);
        let handler = self.handler;
        let config = self.config;

        // Spawn endpoint event loop
        let endpoint_handle = {
            let endpoint_clone = Arc::clone(&endpoint);
            tokio::spawn(async move {
                if let Err(e) = endpoint_clone.run().await {
                    error!("Endpoint error: {}", e);
                }
            })
        };

        // Main server loop - accept connections and handle events
        loop {
            tokio::select! {
                // Accept incoming connections
                connection = endpoint.accept() => {
                    if let Some(conn) = connection {
                        let handler = Arc::clone(&handler);
                        let config = Arc::clone(&config);
                        
                        tokio::spawn(async move {
                            if let Err(e) = Self::handle_connection(conn, handler, config).await {
                                error!("Connection error: {}", e);
                            }
                        });
                    }
                }
                
                // Handle endpoint events
                event = endpoint.next_event() => {
                    if let Some(event) = event {
                        Self::handle_endpoint_event_static(event).await;
                    }
                }
                
                // Handle shutdown signal (Ctrl+C)
                _ = tokio::signal::ctrl_c() => {
                    info!("Received shutdown signal, closing server");
                    break;
                }
            }
        }

        // Graceful shutdown
        endpoint.close().await.map_err(|e| anyhow::anyhow!("Endpoint close error: {}", e))?;
        endpoint_handle.abort();
        
        Ok(())
    }

    /// Handle an endpoint event (static version)
    async fn handle_endpoint_event_static(event: EndpointEvent) {
        match event {
            EndpointEvent::ConnectionEstablished(conn_id, addr) => {
                info!("🔗 Connection established: {} from {}", conn_id, addr);
            }
            EndpointEvent::ConnectionClosed(conn_id, reason) => {
                info!("🔌 Connection closed: {} ({})", conn_id, reason);
            }
            EndpointEvent::ConnectionFailed(addr, reason) => {
                warn!("❌ Connection failed from {}: {}", addr, reason);
            }
            EndpointEvent::IncomingConnection(_) => {
                // This is handled in the main loop
            }
        }
    }

    /// Handle a new connection
    async fn handle_connection(
        connection: Connection,
        handler: Arc<dyn ConnectionHandler>,
        config: Arc<QuicServerConfig>,
    ) -> Result<()> {
        let remote_addr = connection.remote_address().await;
        
        info!("🔗 New connection from {}", remote_addr);
        debug!("Connection stats: {:?}", connection.stats().await);

        // Use the connection handler to process this connection
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

    /// Get connection count  
    pub async fn connection_count(&self) -> usize {
        // This would need to be stored separately or accessed differently
        // For now, return 0 as a placeholder
        0
    }

    /// Close the server
    pub async fn close(&self) -> Result<()> {
        // Close would need to be handled differently in the new architecture
        Ok(())
    }
}