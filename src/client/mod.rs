use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use futures::stream::Stream;
use quinn::{ClientConfig, Connection, Endpoint, NewConnection, VarInt};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, error, info, warn};

pub mod builder;
pub mod config;
pub mod stream;

pub use builder::QuicClientBuilder;
pub use config::QuicClientConfig;
pub use stream::{BiStream, UniStream};

#[derive(Debug, Clone)]
pub struct QuicClient {
    endpoint: Endpoint,
    config: QuicClientConfig,
}

impl QuicClient {
    pub fn builder() -> QuicClientBuilder {
        QuicClientBuilder::new()
    }

    pub fn new(config: QuicClientConfig) -> Result<Self> {
        let client_config = Self::build_quinn_config(&config)?;
        let endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
        endpoint.set_default_client_config(client_config);

        Ok(Self { endpoint, config })
    }

    pub async fn connect(&self, addr: SocketAddr) -> Result<Connection> {
        let conn = self.endpoint.connect(addr, &self.config.server_name)?.await?;
        info!("Connected to {}", addr);
        Ok(conn)
    }

    pub async fn connect_with_alpn(&self, addr: SocketAddr, alpn: &str) -> Result<Connection> {
        let mut client_config = Self::build_quinn_config(&self.config)?;
        client_config.alpn_protocols = vec![alpn.as_bytes().to_vec()];
        
        let endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
        endpoint.set_default_client_config(client_config);
        
        let conn = endpoint.connect(addr, &self.config.server_name)?.await?;
        info!("Connected to {} with ALPN: {}", addr, alpn);
        Ok(conn)
    }

    pub async fn open_bi_stream(&self, conn: &Connection) -> Result<BiStream> {
        let (send, recv) = conn.open_bi().await?;
        Ok(BiStream::new(send, recv))
    }

    pub async fn open_uni_stream(&self, conn: &Connection) -> Result<UniStream> {
        let send = conn.open_uni().await?;
        Ok(UniStream::new(send))
    }

    fn build_quinn_config(config: &QuicClientConfig) -> Result<ClientConfig> {
        let mut client_config = ClientConfig::new(Arc::new(
            rustls::ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(config.root_certs.clone())
                .with_no_client_auth(),
        ));

        if !config.alpn_protocols.is_empty() {
            client_config.alpn_protocols = config.alpn_protocols.clone();
        }

        Ok(client_config)
    }
}