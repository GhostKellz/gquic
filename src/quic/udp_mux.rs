use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};
use bytes::Bytes;
use anyhow::Result;

use super::connection::{Connection, ConnectionId};
use super::packet::Packet;
use super::error::QuicError;

/// UDP packet received from the network
#[derive(Debug)]
pub struct UdpPacket {
    pub data: Bytes,
    pub source: SocketAddr,
    pub destination: SocketAddr,
}

/// UDP multiplexer for handling multiple QUIC connections over a single socket
pub struct UdpMultiplexer {
    socket: Arc<UdpSocket>,
    connections: Arc<RwLock<HashMap<ConnectionId, Connection>>>,
    packet_tx: mpsc::UnboundedSender<UdpPacket>,
    packet_rx: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<UdpPacket>>>,
    local_addr: SocketAddr,
}

impl UdpMultiplexer {
    /// Create a new UDP multiplexer
    pub async fn new(bind_addr: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr).await
            .map_err(|e| QuicError::Io(e))?;
        
        let local_addr = socket.local_addr()
            .map_err(|e| QuicError::Io(e))?;
        
        let (packet_tx, packet_rx) = mpsc::unbounded_channel();
        
        info!("UDP multiplexer bound to {}", local_addr);
        
        Ok(Self {
            socket: Arc::new(socket),
            connections: Arc::new(RwLock::new(HashMap::new())),
            packet_tx,
            packet_rx: Arc::new(tokio::sync::Mutex::new(packet_rx)),
            local_addr,
        })
    }
    
    /// Get the local address the multiplexer is bound to
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
    
    /// Add a connection to the multiplexer
    pub async fn add_connection(&self, connection: Connection) -> Result<()> {
        let connection_id = connection.connection_id().await;
        let remote_addr = connection.remote_address().await;
        
        let mut connections = self.connections.write().await;
        connections.insert(connection_id.clone(), connection);
        
        info!("Added connection {} for {}", connection_id, remote_addr);
        Ok(())
    }
    
    /// Remove a connection from the multiplexer
    pub async fn remove_connection(&self, connection_id: &ConnectionId) -> Result<()> {
        let mut connections = self.connections.write().await;
        if let Some(_) = connections.remove(connection_id) {
            info!("Removed connection {}", connection_id);
        }
        Ok(())
    }
    
    /// Start the UDP multiplexer event loop
    pub async fn run(&self) -> Result<()> {
        let socket = Arc::clone(&self.socket);
        let connections = Arc::clone(&self.connections);
        let packet_tx = self.packet_tx.clone();
        
        // Spawn packet receiver task
        let recv_socket = Arc::clone(&socket);
        let recv_packet_tx = packet_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = Self::receive_packets(recv_socket, recv_packet_tx).await {
                error!("Packet receiver error: {}", e);
            }
        });
        
        // Main packet processing loop
        let mut packet_rx = self.packet_rx.lock().await;
        while let Some(packet) = packet_rx.recv().await {
            if let Err(e) = self.handle_udp_packet(packet).await {
                error!("Error handling UDP packet: {}", e);
            }
        }
        
        Ok(())
    }
    
    /// Receive packets from the UDP socket
    async fn receive_packets(
        socket: Arc<UdpSocket>,
        packet_tx: mpsc::UnboundedSender<UdpPacket>,
    ) -> Result<()> {
        let mut buffer = vec![0u8; 65536]; // Maximum UDP packet size
        
        loop {
            match socket.recv_from(&mut buffer).await {
                Ok((len, source)) => {
                    let data = Bytes::copy_from_slice(&buffer[..len]);
                    let destination = socket.local_addr().unwrap_or_else(|_| {
                        "0.0.0.0:0".parse().unwrap()
                    });
                    
                    let udp_packet = UdpPacket {
                        data,
                        source,
                        destination,
                    };
                    
                    if let Err(_) = packet_tx.send(udp_packet) {
                        warn!("Failed to send UDP packet to processor");
                        break;
                    }
                }
                Err(e) => {
                    error!("Error receiving UDP packet: {}", e);
                    return Err(QuicError::Io(e));
                }
            }
        }
    }
    
    /// Handle a received UDP packet
    async fn handle_udp_packet(&self, udp_packet: UdpPacket) -> Result<()> {
        // Parse QUIC packet
        let quic_packet = match Packet::decode(&udp_packet.data) {
            Ok(packet) => packet,
            Err(e) => {
                debug!("Failed to decode QUIC packet from {}: {}", udp_packet.source, e);
                return Ok(()); // Not a fatal error
            }
        };
        
        // Extract connection ID from packet
        let connection_id = self.extract_connection_id(&quic_packet)?;
        
        // Find the appropriate connection
        let connections = self.connections.read().await;
        if let Some(connection) = connections.get(&connection_id) {
            // Forward packet to connection
            if let Err(e) = connection.handle_packet(quic_packet).await {
                warn!("Error handling packet for connection {}: {}", connection_id, e);
            }
        } else {
            // No existing connection - this might be a new connection attempt
            debug!("Received packet for unknown connection {}", connection_id);
            // In a real implementation, this would trigger connection creation
        }
        
        Ok(())
    }
    
    /// Extract connection ID from a QUIC packet
    fn extract_connection_id(&self, packet: &Packet) -> Result<ConnectionId> {
        // In a real implementation, this would parse the connection ID from the header
        // For now, we'll create a dummy connection ID based on packet data
        let mut id_bytes = vec![0u8; 8];
        
        // Use first 8 bytes of packet data as connection ID
        let data = &packet.payload;
        let copy_len = std::cmp::min(8, data.len());
        id_bytes[..copy_len].copy_from_slice(&data[..copy_len]);
        
        Ok(ConnectionId::from_bytes(Bytes::from(id_bytes)))
    }
    
    /// Send a packet via the UDP socket
    pub async fn send_packet(&self, packet: Packet, destination: SocketAddr) -> Result<()> {
        let encoded = packet.encode();
        
        match self.socket.send_to(&encoded, destination).await {
            Ok(bytes_sent) => {
                debug!("Sent {} bytes to {}", bytes_sent, destination);
                Ok(())
            }
            Err(e) => {
                error!("Failed to send packet to {}: {}", destination, e);
                Err(QuicError::Io(e))
            }
        }
    }
    
    /// Get statistics for all connections
    pub async fn connection_stats(&self) -> HashMap<ConnectionId, (SocketAddr, String)> {
        let connections = self.connections.read().await;
        let mut stats = HashMap::new();
        
        for (id, connection) in connections.iter() {
            let remote_addr = connection.remote_address().await;
            let state = format!("{:?}", connection.state().await);
            stats.insert(id.clone(), (remote_addr, state));
        }
        
        stats
    }
    
    /// Cleanup closed connections
    pub async fn cleanup_connections(&self) -> Result<()> {
        let mut connections = self.connections.write().await;
        let mut to_remove = Vec::new();
        
        for (id, connection) in connections.iter() {
            match connection.state().await {
                super::connection::ConnectionState::Closed | 
                super::connection::ConnectionState::Failed => {
                    to_remove.push(id.clone());
                }
                _ => {}
            }
        }
        
        for id in to_remove {
            connections.remove(&id);
            info!("Cleaned up closed connection {}", id);
        }
        
        Ok(())
    }
}