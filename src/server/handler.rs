use anyhow::Result;
use async_trait::async_trait;
use quinn::{NewConnection, RecvStream, SendStream};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

use super::config::QuicServerConfig;

#[async_trait]
pub trait ConnectionHandler: Send + Sync {
    async fn handle_connection(
        &self,
        connection: NewConnection,
        config: Arc<QuicServerConfig>,
    ) -> Result<()>;
}

pub struct DefaultHandler;

#[async_trait]
impl ConnectionHandler for DefaultHandler {
    async fn handle_connection(
        &self,
        connection: NewConnection,
        _config: Arc<QuicServerConfig>,
    ) -> Result<()> {
        let remote_addr = connection.connection.remote_address();
        info!("Handling connection from {}", remote_addr);

        // Handle incoming bidirectional streams
        loop {
            tokio::select! {
                stream = connection.bi_streams.accept() => {
                    match stream {
                        Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                            info!("Connection {} closed cleanly", remote_addr);
                            break;
                        }
                        Err(e) => {
                            error!("Stream error from {}: {}", remote_addr, e);
                            break;
                        }
                        Ok((send, recv)) => {
                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_bi_stream(send, recv).await {
                                    error!("Bi-stream error: {}", e);
                                }
                            });
                        }
                    }
                }
                
                stream = connection.uni_streams.accept() => {
                    match stream {
                        Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                            info!("Connection {} closed cleanly", remote_addr);
                            break;
                        }
                        Err(e) => {
                            error!("Uni-stream error from {}: {}", remote_addr, e);
                            break;
                        }
                        Ok(recv) => {
                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_uni_stream(recv).await {
                                    error!("Uni-stream error: {}", e);
                                }
                            });
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

impl DefaultHandler {
    async fn handle_bi_stream(mut send: SendStream, mut recv: RecvStream) -> Result<()> {
        debug!("Handling bidirectional stream");
        
        // Echo server behavior
        let data = recv.read_to_end(64 * 1024).await?;
        debug!("Received {} bytes", data.len());
        
        // Echo back the data
        send.write_all(&data).await?;
        send.finish().await?;
        
        debug!("Echoed {} bytes back", data.len());
        Ok(())
    }

    async fn handle_uni_stream(mut recv: RecvStream) -> Result<()> {
        debug!("Handling unidirectional stream");
        
        let data = recv.read_to_end(64 * 1024).await?;
        debug!("Received {} bytes on uni-stream", data.len());
        
        // Log the data for debugging
        if let Ok(text) = String::from_utf8(data.clone()) {
            info!("Received text: {}", text);
        }
        
        Ok(())
    }
}

/// Handler for gRPC-over-QUIC traffic
pub struct GrpcHandler;

#[async_trait]
impl ConnectionHandler for GrpcHandler {
    async fn handle_connection(
        &self,
        connection: NewConnection,
        config: Arc<QuicServerConfig>,
    ) -> Result<()> {
        let remote_addr = connection.connection.remote_address();
        info!("Handling gRPC connection from {}", remote_addr);

        // Check ALPN for gRPC protocol
        if let Some(alpn) = connection.connection.handshake_data() {
            if let Some(protocol) = alpn.downcast_ref::<quinn::crypto::rustls::HandshakeData>() {
                debug!("ALPN protocol: {:?}", protocol.protocol);
            }
        }

        // TODO: Integrate with tonic for gRPC handling
        // For now, use default handler
        DefaultHandler.handle_connection(connection, config).await
    }
}