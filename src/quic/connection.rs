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
use crate::crypto::{QuicCrypto, PacketKeys, EncryptionLevel, KeyPhase, InitialSecrets};

/// Flow control for streams and connections
#[derive(Debug)]
pub struct FlowController {
    /// Maximum data that can be sent
    pub max_data: u64,
    /// Data already sent
    pub sent_data: u64,
    /// Maximum data that can be received
    pub max_receive_data: u64,
    /// Data already received
    pub received_data: u64,
}

impl FlowController {
    pub fn new(initial_max_data: u64, initial_max_receive_data: u64) -> Self {
        Self {
            max_data: initial_max_data,
            sent_data: 0,
            max_receive_data: initial_max_receive_data,
            received_data: 0,
        }
    }
    
    /// Check if we can send the given amount of data
    pub fn can_send(&self, bytes: u64) -> bool {
        self.sent_data + bytes <= self.max_data
    }
    
    /// Record data sent
    pub fn on_data_sent(&mut self, bytes: u64) -> Result<()> {
        if !self.can_send(bytes) {
            return Err(QuicError::Protocol(super::error::ProtocolError::FlowControlViolation(
                "Flow control limit exceeded".to_string()
            )));
        }
        self.sent_data += bytes;
        Ok(())
    }
    
    /// Record data received
    pub fn on_data_received(&mut self, bytes: u64) -> Result<()> {
        if self.received_data + bytes > self.max_receive_data {
            return Err(QuicError::Protocol(super::error::ProtocolError::FlowControlViolation(
                "Receive flow control limit exceeded".to_string()
            )));
        }
        self.received_data += bytes;
        Ok(())
    }
    
    /// Update maximum sendable data
    pub fn update_max_data(&mut self, new_max: u64) {
        if new_max > self.max_data {
            self.max_data = new_max;
        }
    }
    
    /// Update maximum receivable data
    pub fn update_max_receive_data(&mut self, new_max: u64) {
        if new_max > self.max_receive_data {
            self.max_receive_data = new_max;
        }
    }
    
    /// Get available send window
    pub fn send_window(&self) -> u64 {
        self.max_data.saturating_sub(self.sent_data)
    }
    
    /// Get available receive window
    pub fn receive_window(&self) -> u64 {
        self.max_receive_data.saturating_sub(self.received_data)
    }
}

use serde::{Serialize, Deserialize};

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
    // Crypto state
    crypto: Option<Arc<QuicCrypto>>,
    keys: HashMap<EncryptionLevel, PacketKeys>,
    key_phase: KeyPhase,
    is_client: bool,
    // Flow control
    flow_controller: FlowController,
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
            crypto: None,
            keys: HashMap::new(),
            key_phase: KeyPhase::Zero,
            is_client,
            flow_controller: FlowController::new(65536, 65536), // 64KB initial window
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
    pub async fn initialize_crypto(&self, crypto: Arc<QuicCrypto>) -> Result<()> {
        let mut data = self.data.write().await;
        
        // Derive initial secrets
        let connection_id_bytes = data.connection_id.as_bytes();
        let initial_secrets = crypto.derive_initial_secrets(connection_id_bytes)?;
        
        // Derive packet keys for client and server
        let client_keys = crypto.derive_packet_keys(&initial_secrets.client)?;
        let server_keys = crypto.derive_packet_keys(&initial_secrets.server)?;
        
        // Store keys based on perspective
        if data.is_client {
            data.keys.insert(EncryptionLevel::Initial, client_keys);
        } else {
            data.keys.insert(EncryptionLevel::Initial, server_keys);
        }
        
        data.crypto = Some(crypto);
        
        info!("Crypto initialized for connection {}", data.connection_id);
        Ok(())
    }
    
    /// Get encryption level for current connection state
    fn encryption_level(&self, state: ConnectionState) -> EncryptionLevel {
        match state {
            ConnectionState::Initial => EncryptionLevel::Initial,
            ConnectionState::Handshaking => EncryptionLevel::Handshake,
            ConnectionState::Connected => EncryptionLevel::OneRtt,
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
    
    /// Check if data can be sent (flow control)
    pub async fn can_send(&self, bytes: u64) -> bool {
        let data = self.data.read().await;
        data.flow_controller.can_send(bytes)
    }
    
    /// Record data sent for flow control
    pub async fn on_data_sent(&self, bytes: u64) -> Result<()> {
        let mut data = self.data.write().await;
        data.flow_controller.on_data_sent(bytes)?;
        data.stats.bytes_sent += bytes;
        Ok(())
    }
    
    /// Record data received for flow control
    pub async fn on_data_received(&self, bytes: u64) -> Result<()> {
        let mut data = self.data.write().await;
        data.flow_controller.on_data_received(bytes)?;
        data.stats.bytes_received += bytes;
        Ok(())
    }
    
    /// Update maximum data that can be sent
    pub async fn update_max_data(&self, new_max: u64) {
        let mut data = self.data.write().await;
        data.flow_controller.update_max_data(new_max);
        debug!("Updated max data to {} for connection {}", new_max, data.connection_id);
    }
    
    /// Get available send window
    pub async fn send_window(&self) -> u64 {
        let data = self.data.read().await;
        data.flow_controller.send_window()
    }
    
    /// Get available receive window
    pub async fn receive_window(&self) -> u64 {
        let data = self.data.read().await;
        data.flow_controller.receive_window()
    }
    
    /// Send a packet over the connection
    pub(crate) async fn send_packet(&self, mut packet: Packet) -> Result<()> {
        let data = self.data.read().await;
        
        // Encrypt packet if crypto is available
        if let Some(crypto) = &data.crypto {
            let encryption_level = self.encryption_level(data.state);
            
            if let Some(keys) = data.keys.get(&encryption_level) {
                let header_bytes = packet.header.encode();
                let encrypted_payload = crypto.encrypt_packet(
                    keys,
                    packet.header.packet_number.value(),
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
                let decrypted_payload = crypto.decrypt_packet(
                    keys,
                    packet.header.packet_number.value(),
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
            Frame::Stream { stream_id, offset: _, data, fin: _ } => {
                // Deliver data to the appropriate stream
                let data_guard = self.data.read().await;
                if let Some(handle) = data_guard.bi_streams.get(&stream_id) {
                    if let Err(_) = handle.deliver_data(data).await {
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
                            
                            let header = PacketHeader {
                                packet_type: PacketType::OneRtt,
                                connection_id: Bytes::copy_from_slice(self.connection_id().await.as_bytes()),
                                packet_number,
                                version: None,
                            };
                            
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
}