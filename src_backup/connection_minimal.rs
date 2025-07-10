//! QUIC connection management

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use bytes::Bytes;
use crate::QuicResult;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionId(pub Vec<u8>);

impl ConnectionId {
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }
    
    pub fn random() -> Self {
        Self(vec![1, 2, 3, 4]) // Placeholder
    }
    
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct Connection {
    id: ConnectionId,
    remote_addr: SocketAddr,
    socket: Arc<UdpSocket>,
}

impl Connection {
    pub fn new(id: ConnectionId, remote_addr: SocketAddr, socket: Arc<UdpSocket>) -> Self {
        Self { id, remote_addr, socket }
    }
    
    pub fn id(&self) -> &ConnectionId {
        &self.id
    }
    
    pub async fn send(&self, data: &[u8]) -> QuicResult<()> {
        self.socket.send_to(data, self.remote_addr).await?;
        Ok(())
    }
}
