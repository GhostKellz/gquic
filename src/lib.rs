//! GQUIC - The Definitive Rust QUIC Library
//!
//! GQUIC provides a high-performance, RFC 9000 compliant QUIC implementation
//! for networking, cryptography, and blockchain applications. Designed for:
//! - High-performance networking (VPNs, CDNs, real-time protocols)
//! - Cryptographic applications (secure channels, key exchange, ZK proofs)
//! - Blockchain protocols (DEX trading, node communication, DeFi)
//! - Gaming and real-time applications (low-latency, reliable transport)

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

pub mod error;
pub mod connection;
pub mod packet;
pub mod frame;
pub mod crypto;
pub mod handshake;
pub mod connection_state;
pub mod blockchain;
pub mod tls;
pub mod quic;
pub mod protection;
pub mod flow_control;
pub mod recovery;
pub mod congestion;
pub mod http3;
pub mod mesh;
pub mod proxy;
pub mod quinn_compat;
pub mod quiche_compat;
pub mod zerocopy;
pub mod observability;
pub mod udp_mux_advanced;
pub mod multipath;
pub mod network;
pub mod wireguard;
pub mod derp;
pub mod discovery;
pub mod hardware;
pub mod gaming;
pub mod deployment;
pub mod benchmarks;
pub mod webtransport;
pub mod zero_rtt;
pub mod migration;
pub mod qpack;
pub mod ecn;

pub use error::QuicError;
pub use connection::{Connection, ConnectionId, ConnectionStats};
pub use packet::Packet;
pub use frame::Frame;
pub use crypto::{CryptoBackend, PublicKey, PrivateKey, SharedSecret, Signature};
pub use handshake::{QuicHandshake, HandshakeState};
pub use connection_state::{ConnectionState, ConnectionStateManager};
pub use blockchain::{Transaction, Block, TransactionPool, TxHash, BlockHash};

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
        
        self.connections.insert(conn_id.clone(), conn.clone());
        Ok(conn)
    }

    /// Create a crypto-aware QUIC endpoint with encryption
    pub async fn bind_crypto(addr: SocketAddr, crypto_key: Vec<u8>) -> QuicResult<CryptoEndpoint> {
        let socket = UdpSocket::bind(addr).await
            .map_err(|e| QuicError::Io(e))?;
        
        Ok(CryptoEndpoint {
            socket: Arc::new(socket),
            connections: HashMap::new(),
            crypto_key,
        })
    }
    
    /// Get endpoint statistics for monitoring
    pub fn stats(&self) -> EndpointStats {
        EndpointStats {
            active_connections: self.connections.len(),
            total_connections: self.connections.len(), // Placeholder
        }
    }
}

/// Crypto-enhanced QUIC endpoint for blockchain/crypto applications
pub struct CryptoEndpoint {
    socket: Arc<UdpSocket>,
    connections: HashMap<ConnectionId, Connection>,
    crypto_key: Vec<u8>,
}

impl CryptoEndpoint {
    /// Accept encrypted connections
    pub async fn accept_encrypted(&mut self) -> QuicResult<Connection> {
        let mut buf = vec![0u8; 65535];
        let (len, addr) = self.socket.recv_from(&mut buf).await
            .map_err(|e| QuicError::Io(e))?;
        
        buf.truncate(len);
        let packet = Packet::parse_encrypted(&buf, &self.crypto_key)?;
        
        let conn_id = packet.connection_id();
        let conn = Connection::new(conn_id.clone(), addr, self.socket.clone());
        
        self.connections.insert(conn_id.clone(), conn.clone());
        Ok(conn)
    }
    
    /// Send encrypted data to all connections
    pub async fn broadcast_encrypted(&self, data: &[u8]) -> QuicResult<()> {
        for conn in self.connections.values() {
            conn.send_encrypted(data).await?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct EndpointStats {
    pub active_connections: usize,
    pub total_connections: usize,
}
