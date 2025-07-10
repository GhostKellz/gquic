use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{sleep, Duration, Instant};
use tracing::{debug, error, info, warn};
use bytes::Bytes;

use super::connection::{Connection, ConnectionId, ConnectionState};
use super::packet::{Packet, PacketHeader, PacketNumber, PacketType};
use super::error::{QuicError, ConnectionError, Result};

/// Configuration for QUIC endpoints
#[derive(Debug, Clone)]
pub struct EndpointConfig {
    pub alpn_protocols: Vec<String>,
    pub max_concurrent_connections: usize,
    pub idle_timeout: Duration,
    pub keep_alive_interval: Duration,
    pub max_packet_size: usize,
    pub enable_0rtt: bool,
    pub enable_migration: bool,
}

impl Default for EndpointConfig {
    fn default() -> Self {
        Self {
            alpn_protocols: vec!["gquic".to_string()],
            max_concurrent_connections: 1000,
            idle_timeout: Duration::from_secs(30),
            keep_alive_interval: Duration::from_secs(10),
            max_packet_size: 1452, // Conservative MTU for most networks
            enable_0rtt: true,
            enable_migration: false, // Disable by default for security
        }
    }
}

/// Events from the endpoint
#[derive(Debug)]
pub enum EndpointEvent {
    ConnectionEstablished(ConnectionId, SocketAddr),
    ConnectionClosed(ConnectionId, String),
    ConnectionFailed(SocketAddr, String),
    IncomingConnection(Connection),
}

/// QUIC endpoint that can act as both client and server
#[derive(Debug)]
pub struct Endpoint {
    socket: Arc<UdpSocket>,
    config: EndpointConfig,
    connections: Arc<RwLock<HashMap<ConnectionId, Connection>>>,
    incoming_tx: mpsc::UnboundedSender<Connection>,
    incoming_rx: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<Connection>>>,
    event_tx: mpsc::UnboundedSender<EndpointEvent>,
    event_rx: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<EndpointEvent>>>,
    is_server: bool,
    last_cleanup: Arc<tokio::sync::Mutex<Instant>>,
}

impl Endpoint {
    /// Create a client endpoint
    pub async fn client(bind_addr: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr).await
            .map_err(|e| QuicError::Io(e.to_string()))?;
        
        Self::new(socket, EndpointConfig::default(), false).await
    }
    
    /// Create a server endpoint
    pub async fn server(bind_addr: SocketAddr, config: EndpointConfig) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr).await
            .map_err(|e| QuicError::Io(e.to_string()))?;
        
        Self::new(socket, config, true).await
    }
    
    /// Create a new endpoint with the given socket and configuration
    async fn new(socket: UdpSocket, config: EndpointConfig, is_server: bool) -> Result<Self> {
        let socket = Arc::new(socket);
        let connections = Arc::new(RwLock::new(HashMap::new()));
        let (incoming_tx, incoming_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        
        let endpoint = Self {
            socket,
            config,
            connections,
            incoming_tx,
            incoming_rx: Arc::new(tokio::sync::Mutex::new(incoming_rx)),
            event_tx,
            event_rx: Arc::new(tokio::sync::Mutex::new(event_rx)),
            is_server,
            last_cleanup: Arc::new(tokio::sync::Mutex::new(Instant::now())),
        };
        
        Ok(endpoint)
    }
    
    /// Get the local socket address
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.socket.local_addr().map_err(|e| QuicError::Io(e))
    }
    
    /// Connect to a remote endpoint (client only)
    pub async fn connect(&self, remote_addr: SocketAddr, server_name: &str) -> Result<Connection> {
        if self.is_server {
            return Err(QuicError::Protocol(crate::quic::error::ProtocolError::InvalidPacketFormat("Client trying to accept connections".to_string())));
        }
        
        let connection_id = ConnectionId::new();
        let connection = Connection::new(
            connection_id.clone(),
            remote_addr,
            Arc::clone(&self.socket),
            true, // is_client
        );
        
        // Send initial packet to start handshake
        let initial_packet = self.create_initial_packet(&connection_id, remote_addr).await?;
        connection.send_packet(initial_packet).await?;
        
        // Store connection
        self.connections.write().await.insert(connection_id.clone(), connection.clone());
        
        // Emit event
        let _ = self.event_tx.send(EndpointEvent::ConnectionEstablished(connection_id.clone(), remote_addr));
        
        info!("Initiated connection to {} with ID {}", remote_addr, connection_id);
        Ok(connection)
    }
    
    /// Accept incoming connections (server only)
    pub async fn accept(&self) -> Option<Connection> {
        if !self.is_server {
            return None;
        }
        
        let mut rx = self.incoming_rx.lock().await;
        rx.recv().await
    }
    
    /// Get connection events
    pub async fn next_event(&self) -> Option<EndpointEvent> {
        let mut rx = self.event_rx.lock().await;
        rx.recv().await
    }
    
    /// Run the endpoint's main event loop
    pub async fn run(&self) -> Result<()> {
        let mut buffer = vec![0u8; self.config.max_packet_size];
        let mut cleanup_interval = tokio::time::interval(Duration::from_secs(30));
        
        info!("QUIC endpoint started on {}", self.local_addr()?);
        
        loop {
            tokio::select! {
                // Handle incoming packets
                packet_result = self.socket.recv_from(&mut buffer) => {
                    match packet_result {
                        Ok((size, remote_addr)) => {
                            let packet_data = Bytes::copy_from_slice(&buffer[..size]);
                            if let Err(e) = self.handle_packet(packet_data, remote_addr).await {
                                warn!("Error handling packet from {}: {}", remote_addr, e);
                            }
                        }
                        Err(e) => {
                            error!("Socket receive error: {:?}", e);
                            return Err(QuicError::Io(e.to_string()));
                        }
                    }
                }
                
                // Periodic cleanup
                _ = cleanup_interval.tick() => {
                    self.cleanup_idle_connections().await;
                }
            }
        }
    }
    
    /// Handle an incoming packet
    async fn handle_packet(&self, data: Bytes, remote_addr: SocketAddr) -> Result<()> {
        let packet = match Packet::decode(data) {
            Ok(packet) => packet,
            Err(e) => {
                debug!("Failed to decode packet from {}: {}", remote_addr, e);
                return Ok(()); // Ignore malformed packets
            }
        };
        
        let connection_id = ConnectionId::from_bytes(&packet.header.connection_id);
        
        // Find existing connection or create new one for server
        let connection = {
            let connections = self.connections.read().await;
            connections.get(&connection_id).cloned()
        };
        
        match connection {
            Some(conn) => {
                // Handle packet on existing connection
                conn.handle_packet(packet).await?;
            }
            None if self.is_server && packet.header.packet_type == PacketType::Initial => {
                // New connection attempt on server
                self.handle_new_connection(packet, remote_addr).await?;
            }
            None => {
                debug!("Received packet for unknown connection {} from {}", 
                       connection_id, remote_addr);
            }
        }
        
        Ok(())
    }
    
    /// Handle a new incoming connection (server only)
    async fn handle_new_connection(&self, packet: Packet, remote_addr: SocketAddr) -> Result<()> {
        let connection_id = ConnectionId::from_bytes(&packet.header.connection_id);
        
        // Check connection limits
        {
            let connections = self.connections.read().await;
            if connections.len() >= self.config.max_concurrent_connections {
                warn!("Rejecting connection from {} - too many connections", remote_addr);
                return Ok(()); // Drop the packet
            }
        }
        
        // Create new connection
        let connection = Connection::new(
            connection_id.clone(),
            remote_addr,
            Arc::clone(&self.socket),
            false, // is_client = false for server
        );
        
        // Handle the initial packet
        connection.handle_packet(packet).await?;
        
        // Store connection
        self.connections.write().await.insert(connection_id.clone(), connection.clone());
        
        // Notify about new connection
        let _ = self.incoming_tx.send(connection);
        let _ = self.event_tx.send(EndpointEvent::ConnectionEstablished(connection_id.clone(), remote_addr));
        
        info!("Accepted new connection {} from {}", connection_id, remote_addr);
        Ok(())
    }
    
    /// Create an initial packet for connection establishment
    async fn create_initial_packet(&self, connection_id: &ConnectionId, _remote_addr: SocketAddr) -> Result<Packet> {
        let header = PacketHeader {
            packet_type: PacketType::Initial,
            connection_id: Bytes::copy_from_slice(connection_id.as_bytes()),
            packet_number: PacketNumber::new(0),
            version: Some(1), // QUIC version 1
        };
        
        // For now, send an empty payload - in real implementation this would contain TLS ClientHello
        let payload = Bytes::new();
        
        Ok(Packet::new(header, payload))
    }
    
    /// Clean up idle and closed connections
    async fn cleanup_idle_connections(&self) {
        let mut connections_to_remove = Vec::new();
        
        {
            let connections = self.connections.read().await;
            for (conn_id, connection) in connections.iter() {
                if connection.is_idle().await || connection.state().await == ConnectionState::Closed {
                    connections_to_remove.push(conn_id.clone());
                }
            }
        }
        
        if !connections_to_remove.is_empty() {
            let mut connections = self.connections.write().await;
            for conn_id in connections_to_remove {
                if let Some(_connection) = connections.remove(&conn_id) {
                    debug!("Cleaned up idle/closed connection {}", conn_id);
                    let _ = self.event_tx.send(EndpointEvent::ConnectionClosed(conn_id, "idle timeout".to_string()));
                }
            }
        }
        
        *self.last_cleanup.lock().await = Instant::now();
    }
    
    /// Get connection statistics
    pub async fn connection_count(&self) -> usize {
        self.connections.read().await.len()
    }
    
    /// Get a specific connection by ID
    pub async fn get_connection(&self, connection_id: &ConnectionId) -> Option<Connection> {
        self.connections.read().await.get(connection_id).cloned()
    }
    
    /// Close a specific connection
    pub async fn close_connection(&self, connection_id: &ConnectionId, reason: &str) -> Result<()> {
        if let Some(connection) = self.get_connection(connection_id).await {
            connection.close(0, reason).await?;
            
            // Remove from our tracking
            self.connections.write().await.remove(connection_id);
            
            let _ = self.event_tx.send(EndpointEvent::ConnectionClosed(connection_id.clone(), reason.to_string()));
        }
        
        Ok(())
    }
    
    /// Close the endpoint and all connections
    pub async fn close(&self) -> Result<()> {
        let connections: Vec<_> = {
            let connections = self.connections.read().await;
            connections.keys().cloned().collect()
        };
        
        for conn_id in connections {
            self.close_connection(&conn_id, "endpoint shutdown").await?;
        }
        
        info!("QUIC endpoint closed");
        Ok(())
    }
}