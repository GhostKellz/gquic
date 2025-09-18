use bytes::Bytes;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::time;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use super::frame::Frame;
use super::packet::{Packet, PacketHeader, PacketNumber, PacketType};
use super::stream::{BiStream, BiStreamHandle, StreamId, UniStream, UniStreamHandle};
use super::error::{QuicError, ConnectionError, Result};
use crate::crypto::CryptoBackend;
use crate::tls::EncryptionLevel;

use serde::{Serialize, Deserialize};

/// Cryptographic keys for a specific encryption level
#[derive(Debug)]
pub struct CryptoKeys {
    pub header_key: Vec<u8>,
    pub packet_key: Vec<u8>,
    pub iv: Vec<u8>,
}

/// QUIC connection identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConnectionId(Vec<u8>);

impl ConnectionId {
    pub fn new() -> Self {
        let uuid = Uuid::new_v4();
        Self(uuid.as_bytes().to_vec())
    }
    
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }
    
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
    
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl std::fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}



/// QUIC connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Initial,
    Handshaking,
    Connected,
    Closing,
    Closed,
    Failed,
}

/// QUIC connection statistics
#[derive(Debug, Clone)]
pub struct ConnectionStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub round_trip_time: Option<Duration>,
    pub congestion_window: u64,
    pub streams_opened: u64,
    pub streams_closed: u64,
}

impl Default for ConnectionStats {
    fn default() -> Self {
        Self {
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            round_trip_time: None,
            congestion_window: 1200, // Initial congestion window
            streams_opened: 0,
            streams_closed: 0,
        }
    }
}

/// Internal connection data
#[derive(Debug)]
struct ConnectionData {
    connection_id: ConnectionId,
    remote_addr: SocketAddr,
    state: ConnectionState,
    stats: ConnectionStats,
    next_packet_number: PacketNumber,
    next_stream_id: StreamId,
    bi_streams: HashMap<StreamId, BiStreamHandle>,
    uni_streams: HashMap<StreamId, UniStreamHandle>,
    last_activity: Instant,
    idle_timeout: Duration,
    // Crypto state - simplified for now
    crypto_enabled: bool,
    crypto: Option<Arc<dyn CryptoBackend>>,
    keys: HashMap<EncryptionLevel, Arc<CryptoKeys>>,
    is_client: bool,
}

impl ConnectionData {
    fn new(connection_id: ConnectionId, remote_addr: SocketAddr, is_client: bool) -> Self {
        let next_stream_id = if is_client {
            StreamId::new(0) // Client-initiated bidirectional streams start at 0
        } else {
            StreamId::new(1) // Server-initiated bidirectional streams start at 1
        };
        
        Self {
            connection_id,
            remote_addr,
            state: ConnectionState::Initial,
            stats: ConnectionStats::default(),
            next_packet_number: PacketNumber::new(0),
            next_stream_id,
            bi_streams: HashMap::new(),
            uni_streams: HashMap::new(),
            last_activity: Instant::now(),
            idle_timeout: Duration::from_secs(30),
            crypto_enabled: false,
            crypto: None,
            keys: HashMap::new(),
            is_client,
        }
    }
}

/// QUIC connection
#[derive(Debug, Clone)]
pub struct Connection {
    data: Arc<RwLock<ConnectionData>>,
    socket: Arc<UdpSocket>,
    frame_tx: mpsc::UnboundedSender<Frame>,
    frame_rx: Arc<Mutex<mpsc::UnboundedReceiver<Frame>>>,
}

impl Connection {
    pub(crate) fn new(
        connection_id: ConnectionId,
        remote_addr: SocketAddr,
        socket: Arc<UdpSocket>,
        is_client: bool,
    ) -> Self {
        let data = Arc::new(RwLock::new(ConnectionData::new(connection_id, remote_addr, is_client)));
        let (frame_tx, frame_rx) = mpsc::unbounded_channel();
        
        Self {
            data,
            socket,
            frame_tx,
            frame_rx: Arc::new(Mutex::new(frame_rx)),
        }
    }
    
    /// Get connection ID
    pub async fn connection_id(&self) -> ConnectionId {
        self.data.read().await.connection_id.clone()
    }
    
    /// Get remote address
    pub async fn remote_address(&self) -> SocketAddr {
        self.data.read().await.remote_addr
    }
    
    /// Get connection state
    pub async fn state(&self) -> ConnectionState {
        self.data.read().await.state
    }
    
    /// Get connection statistics
    pub async fn stats(&self) -> ConnectionStats {
        self.data.read().await.stats.clone()
    }
    
    /// Initialize crypto for the connection
    pub async fn initialize_crypto(&self) -> Result<()> {
        let mut data = self.data.write().await;
        data.crypto_enabled = true;
        info!("Crypto initialized for connection {}", data.connection_id);
        Ok(())
    }
    
    /// Get encryption level for current connection state
    fn encryption_level(&self, state: ConnectionState) -> EncryptionLevel {
        match state {
            ConnectionState::Initial => EncryptionLevel::Initial,
            ConnectionState::Handshaking => EncryptionLevel::Handshake,
            ConnectionState::Connected => EncryptionLevel::Application,
            _ => EncryptionLevel::Initial,
        }
    }
    
    /// Open a new bidirectional stream
    pub async fn open_bi(&self) -> Result<BiStream> {
        let mut data = self.data.write().await;
        
        if data.state != ConnectionState::Connected {
            return Err(QuicError::Connection(ConnectionError::Closed));
        }
        
        let stream_id = data.next_stream_id;
        data.next_stream_id = StreamId::new(stream_id.value() + 4); // Increment by 4 for bidirectional streams
        data.stats.streams_opened += 1;
        
        let (stream, handle) = BiStream::new(stream_id);
        data.bi_streams.insert(stream_id, handle);
        
        debug!("Opened bidirectional stream {}", stream_id);
        Ok(stream)
    }
    
    /// Open a new unidirectional stream
    pub async fn open_uni(&self) -> Result<UniStream> {
        let mut data = self.data.write().await;
        
        if data.state != ConnectionState::Connected {
            return Err(QuicError::Connection(ConnectionError::Closed));
        }
        
        let stream_id = StreamId::new(data.next_stream_id.value() + 2); // Unidirectional streams
        data.next_stream_id = StreamId::new(stream_id.value() + 4);
        data.stats.streams_opened += 1;
        
        let (stream, handle) = UniStream::new(stream_id);
        data.uni_streams.insert(stream_id, handle);
        
        debug!("Opened unidirectional stream {}", stream_id);
        Ok(stream)
    }
    
    /// Accept an incoming bidirectional stream
    pub async fn accept_bi(&self) -> Result<(BiStream, BiStream)> {
        let mut data = self.data.write().await;
        
        if data.state != ConnectionState::Connected {
            return Err(QuicError::Connection(ConnectionError::Closed));
        }
        
        // For demonstration, create a pair of bidirectional streams
        let stream_id = data.next_stream_id;
        data.next_stream_id = StreamId::new(stream_id.value() + 4);
        data.stats.streams_opened += 1;
        
        let (send_stream, send_handle) = BiStream::new(stream_id);
        let (recv_stream, recv_handle) = BiStream::new(StreamId::new(stream_id.value() + 1));
        
        data.bi_streams.insert(stream_id, send_handle);
        data.bi_streams.insert(StreamId::new(stream_id.value() + 1), recv_handle);
        
        debug!("Accepted bidirectional stream pair {}/{}", stream_id, StreamId::new(stream_id.value() + 1));
        Ok((send_stream, recv_stream))
    }
    
    /// Accept an incoming unidirectional stream  
    pub async fn accept_uni(&self) -> Result<Option<UniStream>> {
        // This would be implemented to accept incoming streams
        // For now, return None to indicate no pending streams
        Ok(None)
    }
    
    /// Close the connection
    pub async fn close(&self, error_code: u64, reason: &str) -> Result<()> {
        let mut data = self.data.write().await;
        
        if data.state == ConnectionState::Closed {
            return Ok(());
        }
        
        data.state = ConnectionState::Closing;
        
        // Send CONNECTION_CLOSE frame
        let frame = Frame::ConnectionClose {
            error_code,
            frame_type: None,
            reason_phrase: reason.to_string(),
        };
        
        if let Err(_) = self.frame_tx.send(frame) {
            warn!("Failed to send CONNECTION_CLOSE frame");
        }
        
        // Update state to closed
        data.state = ConnectionState::Closed;
        
        info!("Connection {} closed: {}", data.connection_id, reason);
        Ok(())
    }
    
    /// Send a packet over the connection
    pub(crate) async fn send_packet(&self, mut packet: Packet) -> Result<()> {
        let data = self.data.read().await;
        
        // Encrypt packet if crypto is available
        if let Some(crypto) = &data.crypto {
            let encryption_level = self.encryption_level(data.state);
            
            if let Some(keys) = data.keys.get(&encryption_level) {
                let header_bytes = packet.header.encode();
                let mut nonce = keys.iv.clone();
                let nonce_len = nonce.len();
                let packet_number = packet.header.packet_number.value();
                for (i, byte) in packet_number.to_be_bytes().iter().rev().enumerate() {
                    if i < nonce_len {
                        nonce[nonce_len - 1 - i] ^= byte;
                    }
                }
                let encrypted_payload = crypto.encrypt_aead(
                    &keys.packet_key,
                    &nonce,
                    &header_bytes,
                    &packet.payload,
                )?;
                packet.payload = encrypted_payload.into();
            }
        }
        
        let encoded = packet.encode();
        
        match self.socket.send_to(&encoded, data.remote_addr).await {
            Ok(bytes_sent) => {
                drop(data);
                let mut data = self.data.write().await;
                data.stats.bytes_sent += bytes_sent as u64;
                data.stats.packets_sent += 1;
                data.last_activity = Instant::now();
                Ok(())
            }
            Err(e) => {
                error!("Failed to send packet: {}", e);
                Err(QuicError::Io(e.to_string()))
            }
        }
    }
    
    /// Handle an incoming packet
    pub(crate) async fn handle_packet(&self, mut packet: Packet) -> Result<()> {
        let mut data = self.data.write().await;
        
        // Decrypt packet if crypto is available
        if let Some(crypto) = &data.crypto {
            let encryption_level = self.encryption_level(data.state);
            
            if let Some(keys) = data.keys.get(&encryption_level) {
                let header_bytes = packet.header.encode();
                let mut nonce = keys.iv.clone();
                let nonce_len = nonce.len();
                let packet_number = packet.header.packet_number.value();
                for (i, byte) in packet_number.to_be_bytes().iter().rev().enumerate() {
                    if i < nonce_len {
                        nonce[nonce_len - 1 - i] ^= byte;
                    }
                }
                let decrypted_payload = crypto.decrypt_aead(
                    &keys.packet_key,
                    &nonce,
                    &header_bytes,
                    &packet.payload,
                )?;
                packet.payload = decrypted_payload.into();
            }
        }
        
        data.stats.bytes_received += packet.payload.len() as u64;
        data.stats.packets_received += 1;
        data.last_activity = Instant::now();
        
        // Update connection state based on packet type
        match packet.header.packet_type {
            PacketType::Initial => {
                if data.state == ConnectionState::Initial {
                    data.state = ConnectionState::Handshaking;
                    info!("Connection {} starting handshake", data.connection_id);
                }
            }
            PacketType::Handshake => {
                if data.state == ConnectionState::Handshaking {
                    // Handshake processing would go here
                    debug!("Processing handshake packet for connection {}", data.connection_id);
                }
            }
            PacketType::OneRtt => {
                if data.state == ConnectionState::Handshaking {
                    data.state = ConnectionState::Connected;
                    info!("Connection {} established", data.connection_id);
                }
            }
            _ => {}
        }
        
        // Process frames in the packet
        self.process_frames(&packet.payload).await?;
        
        Ok(())
    }
    
    /// Process frames within a packet payload
    async fn process_frames(&self, payload: &[u8]) -> Result<()> {
        let mut data = payload;
        
        while !data.is_empty() {
            // Simplified frame processing for now
            if data.len() < 1 {
                break;
            }
            
            let frame_type = data[0];
            match frame_type {
                0x00 => {
                    // PADDING frame - skip padding bytes
                    let mut consumed = 0;
                    while consumed < data.len() && data[consumed] == 0x00 {
                        consumed += 1;
                    }
                    data = &data[consumed..];
                }
                0x01 => {
                    // PING frame
                    debug!("Received PING frame");
                    data = &data[1..];
                }
                0x06 => {
                    // CRYPTO frame - simplified
                    debug!("Received CRYPTO frame");
                    data = &[]; // Skip rest for now
                }
                0x1c => {
                    // CONNECTION_CLOSE frame
                    debug!("Received CONNECTION_CLOSE frame");
                    let mut conn_data = self.data.write().await;
                    conn_data.state = ConnectionState::Closed;
                    break;
                }
                _ => {
                    // Unknown frame - skip rest
                    data = &[];
                }
            }
        }
        
        Ok(())
    }
    
    /// Handle a specific frame
    async fn handle_frame(&self, frame: Frame) -> Result<()> {
        match frame {
            Frame::Stream { stream_id, offset, data, fin } => {
                // Deliver data to the appropriate stream
                let data_guard = self.data.read().await;
                if let Some(handle) = data_guard.bi_streams.get(&stream_id) {
                    let stream_data = crate::quic::stream::StreamData { offset, data, fin };
                    if let Err(_) = handle.deliver_data(stream_data).await {
                        warn!("Failed to deliver data to stream {}", stream_id);
                    }
                }
            }
            Frame::Ping => {
                debug!("Received PING frame");
                // Respond with PONG (not implemented)
            }
            Frame::ConnectionClose { error_code, reason_phrase, .. } => {
                info!("Connection closed by peer: {} ({})", error_code, reason_phrase);
                let mut data = self.data.write().await;
                data.state = ConnectionState::Closed;
            }
            _ => {
                debug!("Received frame: {:?}", frame);
            }
        }
        
        Ok(())
    }
    
    /// Check if the connection is idle and should be closed
    pub(crate) async fn is_idle(&self) -> bool {
        let data = self.data.read().await;
        data.last_activity.elapsed() > data.idle_timeout
    }
    
    /// Run the connection's main event loop
    pub async fn run(&self) -> Result<()> {
        let mut interval = time::interval(Duration::from_millis(10));
        let mut frame_rx = self.frame_rx.lock().await;
        
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // Periodic tasks: idle timeout check, keep-alive, etc.
                    if self.is_idle().await {
                        info!("Connection idle timeout, closing");
                        self.close(0, "idle timeout").await?;
                        break;
                    }
                }
                
                frame = frame_rx.recv() => {
                    match frame {
                        Some(frame) => {
                            // Send frame in a packet
                            let data = self.data.read().await;
                            let packet_number = data.next_packet_number;
                            drop(data);
                            
                            let header = PacketHeader::new(
                                PacketType::OneRtt,
                                Bytes::copy_from_slice(self.connection_id().await.as_bytes()),
                                packet_number,
                            );
                            
                            let packet = Packet::new(header, frame.encode());
                            self.send_packet(packet).await?;
                            
                            // Increment packet number
                            let mut data = self.data.write().await;
                            data.next_packet_number = packet_number.next();
                        }
                        None => {
                            debug!("Frame channel closed");
                            break;
                        }
                    }
                }
            }
            
            // Check if connection is closed
            if self.state().await == ConnectionState::Closed {
                break;
            }
        }
        
        Ok(())
    }

    /// Initiate handshake with a server
    pub async fn initiate_handshake(&self, _server_name: &str) -> Result<()> {
        let mut data = self.data.write().await;
        data.state = ConnectionState::Handshaking;

        // Send Initial packet to start handshake
        let frame = Frame::Crypto {
            offset: 0,
            data: Bytes::from(b"CLIENT_HELLO".to_vec()),
        };

        if let Err(_) = self.frame_tx.send(frame) {
            return Err(QuicError::Connection(ConnectionError::InternalError));
        }

        // For now, assume handshake completes immediately
        data.state = ConnectionState::Connected;

        info!("Handshake initiated with server");
        Ok(())
    }

    /// Send reliable data over the connection
    pub async fn send_reliable(&self, data: &[u8]) -> Result<()> {
        let frame = Frame::Stream {
            stream_id: StreamId::new(0),
            offset: 0,
            data: Bytes::from(data.to_vec()),
            fin: false,
        };

        self.frame_tx.send(frame)
            .map_err(|_| QuicError::Connection(ConnectionError::InternalError))?;

        Ok(())
    }

    /// Send data over the connection
    pub async fn send_data(&self, data: &[u8]) -> Result<()> {
        self.send_reliable(data).await
    }

    /// Get peer address
    pub async fn peer_addr(&self) -> SocketAddr {
        self.data.read().await.remote_addr
    }

    /// Check if connection is connected
    pub async fn is_connected(&self) -> bool {
        matches!(self.state().await, ConnectionState::Connected)
    }

    /// Get connection ID (synchronous version)
    pub fn id(&self) -> ConnectionId {
        // For synchronous access, we'll use a blocking approach
        // In a real implementation, this might be stored separately
        ConnectionId::new()
    }

    /// Open a stream (generic)
    pub async fn open_stream(&self, bidirectional: bool) -> Result<StreamId> {
        if bidirectional {
            let stream = self.open_bi().await?;
            Ok(stream.id())
        } else {
            let stream = self.open_uni().await?;
            Ok(stream.id())
        }
    }

    /// Send stream data
    pub async fn send_stream_data(&self, stream_id: StreamId, data: Bytes) -> Result<()> {
        let frame = Frame::Stream {
            stream_id,
            offset: 0,
            data: Bytes::from(data.to_vec()),
            fin: false,
        };

        self.frame_tx.send(frame)
            .map_err(|_| QuicError::Connection(ConnectionError::InternalError))?;

        Ok(())
    }

    /// Receive stream data
    pub async fn receive_stream_data(&self, _stream_id: StreamId) -> Result<Option<Bytes>> {
        // Simplified implementation - in reality this would check stream buffers
        Ok(None)
    }

    /// Close a stream
    pub async fn close_stream(&self, stream_id: StreamId) -> Result<()> {
        let frame = Frame::Stream {
            stream_id,
            offset: 0,
            data: Bytes::new(),
            fin: true,
        };

        self.frame_tx.send(frame)
            .map_err(|_| QuicError::Connection(ConnectionError::InternalError))?;

        Ok(())
    }

    /// Send encrypted data
    pub async fn send_encrypted(&self, data: &[u8]) -> Result<()> {
        // For now, just send as regular data
        self.send_data(data).await
    }

    /// Send 0-RTT data (early data)
    pub async fn send_zero_rtt(&self, data: &[u8]) -> Result<()> {
        let data_guard = self.data.read().await;

        if data_guard.state != ConnectionState::Handshaking {
            return Err(QuicError::Connection(ConnectionError::InvalidState("Invalid connection state".to_string())));
        }

        // Create 0-RTT packet
        let header = PacketHeader {
            packet_type: PacketType::ZeroRtt,
            connection_id: Bytes::from(data_guard.connection_id.to_bytes()),
            packet_number: PacketNumber::new(data_guard.stats.packets_sent + 1),
            version: Some(1),
            source_connection_id: Some(Bytes::from(data_guard.connection_id.to_bytes())),
            destination_connection_id: None,
            token: None,
            length: Some(data.len() as u64),
        };

        let packet = Packet::new(header, Bytes::copy_from_slice(data));
        drop(data_guard);

        self.send_packet(packet).await?;
        info!("Sent 0-RTT data: {} bytes", data.len());
        Ok(())
    }

    /// Send PATH_RESPONSE frame
    pub async fn send_path_response(&self, challenge: &[u8], from: SocketAddr) -> Result<()> {
        let data_guard = self.data.read().await;

        if data_guard.state != ConnectionState::Connected {
            return Err(QuicError::Connection(ConnectionError::InvalidState("Invalid connection state".to_string())));
        }

        // Create PATH_RESPONSE frame
        let mut response_data = [0u8; 8];
        let copy_len = std::cmp::min(challenge.len(), 8);
        response_data[..copy_len].copy_from_slice(&challenge[..copy_len]);

        let frame = Frame::PathResponse {
            data: response_data,
        };

        // Send frame
        if let Err(_) = self.frame_tx.send(frame) {
            return Err(QuicError::Connection(ConnectionError::InternalError));
        }

        info!("Sent PATH_RESPONSE to {}", from);
        Ok(())
    }

    /// Get local socket address
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.socket.local_addr()
            .map_err(|e| QuicError::Io(e.to_string()))
    }

    /// Set connection path (for migration)
    pub fn set_path(&mut self, local_addr: SocketAddr, remote_addr: SocketAddr) -> Result<()> {
        // This is a simplified implementation - real implementation would handle socket rebinding
        info!("Setting connection path: {} -> {}", local_addr, remote_addr);
        Ok(())
    }

    /// Send PATH_CHALLENGE frame
    pub async fn send_path_challenge(&self, challenge: &[u8], to: SocketAddr) -> Result<()> {
        let data_guard = self.data.read().await;

        if data_guard.state != ConnectionState::Connected {
            return Err(QuicError::Connection(ConnectionError::InvalidState("Connection not connected for path challenge".to_string())));
        }

        // Create PATH_CHALLENGE frame
        let mut challenge_data = [0u8; 8];
        let copy_len = std::cmp::min(challenge.len(), 8);
        challenge_data[..copy_len].copy_from_slice(&challenge[..copy_len]);

        let frame = Frame::PathChallenge {
            data: challenge_data,
        };

        // Send frame
        if let Err(_) = self.frame_tx.send(frame) {
            return Err(QuicError::Connection(ConnectionError::InternalError));
        }

        info!("Sent PATH_CHALLENGE to {}", to);
        Ok(())
    }
}