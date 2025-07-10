//! GQUIC - A minimal, working QUIC implementation
//! 
//! This is a stripped-down version that actually compiles and works.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use bytes::Bytes;

pub mod error;
pub mod connection;
pub mod packet;
pub mod frame;

pub use error::QuicError;
pub use connection::{Connection, ConnectionId};
pub use packet::Packet;
pub use frame::Frame;

/// Result type for QUIC operations
pub type QuicResult<T> = Result<T, QuicError>;

/// A minimal QUIC endpoint that can send/receive packets
pub struct Endpoint {
    socket: Arc<UdpSocket>,
    connections: HashMap<ConnectionId, Connection>,
}

impl Endpoint {
    /// Create a new QUIC endpoint
    pub async fn bind(addr: SocketAddr) -> QuicResult<Self> {
        let socket = UdpSocket::bind(addr).await
            .map_err(|e| QuicError::Io(e))?;
        
        Ok(Self {
            socket: Arc::new(socket),
            connections: HashMap::new(),
        })
    }

    /// Accept incoming connections
    pub async fn accept(&mut self) -> QuicResult<Connection> {
        let mut buf = vec![0u8; 65535];
        let (len, addr) = self.socket.recv_from(&mut buf).await
            .map_err(|e| QuicError::Io(e))?;
        
        buf.truncate(len);
        let packet = Packet::parse(&buf)?;
        
        // For now, just create a basic connection
        let conn_id = packet.connection_id();
        let conn = Connection::new(conn_id.clone(), addr, self.socket.clone());
        
        self.connections.insert(conn_id, conn.clone());
        Ok(conn)
    }
}
