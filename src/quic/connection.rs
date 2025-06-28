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

/// QUIC connection identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionId(Bytes);

impl ConnectionId {
    pub fn new() -> Self {
        let uuid = Uuid::new_v4();
        Self(Bytes::copy_from_slice(uuid.as_bytes()))
    }
    
    pub fn from_bytes(bytes: Bytes) -> Self {
        Self(bytes)
    }
    
    pub fn as_bytes(&self) -> &Bytes {
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
    pub async fn accept_bi(&self) -> Result<Option<BiStream>> {
        // This would be implemented to accept incoming streams
        // For now, return None to indicate no pending streams
        Ok(None)
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
    pub(crate) async fn send_packet(&self, packet: Packet) -> Result<()> {
        let data = self.data.read().await;
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
                Err(QuicError::Io(e))
            }
        }
    }
    
    /// Handle an incoming packet
    pub(crate) async fn handle_packet(&self, packet: Packet) -> Result<()> {
        let mut data = self.data.write().await;
        data.stats.bytes_received += packet.payload.len() as u64;
        data.stats.packets_received += 1;
        data.last_activity = Instant::now();
        
        // Update connection state based on packet type
        match packet.header.packet_type {
            PacketType::Initial => {
                if data.state == ConnectionState::Initial {
                    data.state = ConnectionState::Handshaking;
                }
            }
            PacketType::Handshake => {
                if data.state == ConnectionState::Handshaking {
                    // Handshake processing would go here
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
    async fn process_frames(&self, payload: &Bytes) -> Result<()> {
        let mut data = payload.as_ref();
        
        while !data.is_empty() {
            match Frame::decode(data) {
                Ok((frame, consumed)) => {
                    data = &data[consumed..];
                    self.handle_frame(frame).await?;
                }
                Err(e) => {
                    warn!("Failed to decode frame: {}", e);
                    break;
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
                                connection_id: self.connection_id().await.as_bytes().clone(),
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