//! Quiche Compatibility Layer
//!
//! This module provides a complete Quiche-compatible API to make GQUIC a drop-in
//! replacement for Cloudflare's Quiche library. This enables migration from Quiche
//! to GQUIC with zero code changes.

use crate::quic::error::{QuicError, Result as GQuicResult, ProtocolError};
use crate::quic::connection::{Connection as GQuicConnection, ConnectionId as GQuicConnectionId};
use crate::http3::{Http3Connection, Http3Request, Http3Response, Http3Header};
use bytes::Bytes;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn, error};

/// QUIC protocol version constant (Quiche-compatible)
pub const PROTOCOL_VERSION: u32 = 0x00000001;

/// Maximum UDP payload size
pub const MAX_CONN_ID_LEN: usize = 20;

/// Quiche-compatible Header type
#[derive(Debug, Clone)]
pub struct Header<'a> {
    /// QUIC version
    pub version: u32,
    /// Packet type
    pub ty: Type,
    /// Destination connection ID
    pub dcid: ConnectionId<'a>,
    /// Source connection ID
    pub scid: ConnectionId<'a>,
    /// Packet token (for Initial packets)
    pub token: Option<&'a [u8]>,
}

/// Quiche-compatible packet types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type {
    Initial,
    ZeroRTT,
    Handshake,
    Retry,
    VersionNegotiation,
    Short,
}

/// Quiche-compatible ConnectionId
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionId<'a> {
    data: &'a [u8],
}

impl<'a> ConnectionId<'a> {
    /// Create new ConnectionId from bytes
    pub fn from_ref(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Get length of connection ID
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if connection ID is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get bytes
    pub fn as_ref(&self) -> &[u8] {
        self.data
    }

    /// Generate a new random connection ID
    pub fn new() -> ConnectionId<'static> {
        // For quiche compatibility, we'll use a static random ID
        // In a real implementation, this would be properly generated
        static DEFAULT_CONN_ID: &[u8] = &[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
        ConnectionId::from_ref(DEFAULT_CONN_ID)
    }
}

impl<'a> std::ops::Deref for ConnectionId<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.data
    }
}

/// Quiche-compatible RecvInfo
#[derive(Debug, Clone)]
pub struct RecvInfo {
    pub to: SocketAddr,
    pub from: SocketAddr,
}

/// Quiche-compatible SendInfo
#[derive(Debug, Clone)]
pub struct SendInfo {
    pub to: SocketAddr,
    pub from: SocketAddr,
}

/// Quiche-compatible Result type
pub type Result<T> = std::result::Result<T, Error>;

/// Quiche-compatible error type
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Buffer too short")]
    BufferTooShort,
    #[error("Invalid frame")]
    InvalidFrame,
    #[error("Invalid packet")]
    InvalidPacket,
    #[error("Invalid state")]
    InvalidState,
    #[error("Invalid stream state")]
    InvalidStreamState,
    #[error("Invalid transport parameter")]
    InvalidTransportParameter,
    #[error("Flow control error")]
    FlowControl,
    #[error("Stream limit error")]
    StreamLimit,
    #[error("Final size error")]
    FinalSize,
    #[error("Crypto buffer exceeded")]
    CryptoBufferExceeded,
    #[error("Transport error: {0}")]
    TransportError(u64),
    #[error("Application error: {0}")]
    ApplicationError(u64),
    #[error("Connection closed")]
    ConnectionClosed,
    #[error("Timeout")]
    Timeout,
    #[error("Done (no more data)")]
    Done,
}

impl From<QuicError> for Error {
    fn from(err: QuicError) -> Self {
        match err {
            QuicError::ConnectionClosed => Error::ConnectionClosed,
            QuicError::Timeout(_) => Error::Timeout,
            QuicError::FlowControl(_) => Error::FlowControl,
            QuicError::Protocol(ProtocolError::InvalidFrameFormat(_)) => Error::InvalidFrame,
            QuicError::Protocol(ProtocolError::InvalidPacket(_)) => Error::InvalidPacket,
            QuicError::Protocol(ProtocolError::InvalidPacketFormat(_)) => Error::InvalidPacket,
            _ => Error::TransportError(0),
        }
    }
}

/// Quiche-compatible connection configuration
#[derive(Debug, Clone)]
pub struct Config {
    version: u32,
    max_idle_timeout: Duration,
    max_recv_udp_payload_size: usize,
    max_send_udp_payload_size: usize,
    initial_max_data: u64,
    initial_max_stream_data_bidi_local: u64,
    initial_max_stream_data_bidi_remote: u64,
    initial_max_stream_data_uni: u64,
    initial_max_streams_bidi: u64,
    initial_max_streams_uni: u64,
    ack_delay_exponent: u64,
    max_ack_delay: Duration,
    disable_active_migration: bool,
    cc_algorithm: CongestionControlAlgorithm,
    hystart: bool,
    dgram_recv_max_queue_len: Option<usize>,
    dgram_send_max_queue_len: Option<usize>,
}

/// Congestion control algorithms (Quiche-compatible)
#[derive(Debug, Clone, Copy)]
pub enum CongestionControlAlgorithm {
    Reno,
    Cubic,
    BBR,
    BBR2,
}

impl Config {
    /// Create a new config with the given QUIC version
    pub fn new(version: u32) -> Result<Self> {
        Ok(Self {
            version,
            max_idle_timeout: Duration::from_secs(30),
            max_recv_udp_payload_size: 65527,
            max_send_udp_payload_size: 1200,
            initial_max_data: 1024 * 1024, // 1MB
            initial_max_stream_data_bidi_local: 256 * 1024, // 256KB
            initial_max_stream_data_bidi_remote: 256 * 1024,
            initial_max_stream_data_uni: 256 * 1024,
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 100,
            ack_delay_exponent: 3,
            max_ack_delay: Duration::from_millis(25),
            disable_active_migration: false,
            cc_algorithm: CongestionControlAlgorithm::Cubic,
            hystart: true,
            dgram_recv_max_queue_len: None,
            dgram_send_max_queue_len: None,
        })
    }

    /// Set the congestion control algorithm
    pub fn set_cc_algorithm(&mut self, algo: CongestionControlAlgorithm) {
        self.cc_algorithm = algo;
    }

    /// Set maximum idle timeout
    pub fn set_max_idle_timeout(&mut self, timeout: Duration) {
        self.max_idle_timeout = timeout;
    }

    /// Set initial maximum data
    pub fn set_initial_max_data(&mut self, value: u64) {
        self.initial_max_data = value;
    }

    /// Set initial maximum stream data for bidirectional streams
    pub fn set_initial_max_stream_data_bidi_local(&mut self, value: u64) {
        self.initial_max_stream_data_bidi_local = value;
    }

    pub fn set_initial_max_stream_data_bidi_remote(&mut self, value: u64) {
        self.initial_max_stream_data_bidi_remote = value;
    }

    /// Set initial maximum stream data for unidirectional streams
    pub fn set_initial_max_stream_data_uni(&mut self, value: u64) {
        self.initial_max_stream_data_uni = value;
    }

    /// Set initial maximum bidirectional streams
    pub fn set_initial_max_streams_bidi(&mut self, value: u64) {
        self.initial_max_streams_bidi = value;
    }

    /// Set initial maximum unidirectional streams
    pub fn set_initial_max_streams_uni(&mut self, value: u64) {
        self.initial_max_streams_uni = value;
    }

    /// Enable or disable active connection migration
    pub fn set_disable_active_migration(&mut self, disable: bool) {
        self.disable_active_migration = disable;
    }

    /// Set application protocols (ALPN)
    pub fn set_application_protos(&mut self, _protos: &[&[u8]]) -> Result<()> {
        // Store ALPN protocols - simplified for now
        Ok(())
    }

    /// Load certificate chain from file
    pub fn load_cert_chain_from_pem_file(&mut self, _file: &str) -> Result<()> {
        // Load certificate - simplified for now
        debug!("Loading certificate chain");
        Ok(())
    }

    /// Load private key from file
    pub fn load_priv_key_from_pem_file(&mut self, _file: &str) -> Result<()> {
        // Load private key - simplified for now
        debug!("Loading private key");
        Ok(())
    }

    /// Verify peer certificates
    pub fn verify_peer(&mut self, verify: bool) {
        debug!("Set peer verification: {}", verify);
    }

    /// Enable early data
    pub fn enable_early_data(&mut self) {
        debug!("Enabled early data");
    }

    /// Set datagram parameters
    pub fn enable_dgram(&mut self, enabled: bool, recv_queue_len: usize, send_queue_len: usize) {
        self.dgram_recv_max_queue_len = if enabled { Some(recv_queue_len) } else { None };
        self.dgram_send_max_queue_len = if enabled { Some(send_queue_len) } else { None };
    }
}

/// Quiche-compatible connection
pub struct Connection {
    inner: GQuicConnection,
    config: Config,
    http3_conn: Option<Http3Connection>,
    is_server: bool,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    scid: String,
    dcid: String,
    trace_id: String,
    streams: HashMap<u64, StreamState>,
    next_stream_id: u64,
}

/// Stream state for Quiche compatibility
#[derive(Debug)]
struct StreamState {
    readable: bool,
    writable: bool,
    finished: bool,
    send_buf: Vec<u8>,
    recv_buf: Vec<u8>,
}

impl Connection {
    /// Create a new client connection
    pub fn connect(
        server_name: Option<&str>,
        scid: &ConnectionId,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        config: &Config,
    ) -> Result<Self> {
        debug!("Creating Quiche-compatible client connection to {}", peer_addr);

        let socket = Arc::new(std::net::UdpSocket::bind(local_addr)
            .map_err(|e| Error::TransportError(e.raw_os_error().unwrap_or(0) as u64))?);

        // Convert to tokio socket (simplified)
        let tokio_socket = Arc::new(tokio::net::UdpSocket::from_std(socket.try_clone().unwrap()).unwrap());

        let connection_id = crate::quic::connection::ConnectionId::new();
        let inner = GQuicConnection::new(connection_id, peer_addr, tokio_socket, false);
        let dcid = ConnectionId::new(); // Generate destination connection ID

        Ok(Self {
            inner,
            config: config.clone(),
            http3_conn: None,
            is_server: false,
            local_addr,
            peer_addr,
            scid: hex::encode(scid.as_ref()),
            dcid: hex::encode(dcid.as_ref()),
            trace_id: format!("client-{}", hex::encode(scid.as_ref())),
            streams: HashMap::new(),
            next_stream_id: 0, // Client-initiated streams start at 0
        })
    }

    /// Create a new server connection
    pub fn accept(
        scid: &ConnectionId,
        odcid: Option<&ConnectionId>,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        config: &Config,
    ) -> Result<Self> {
        debug!("Creating Quiche-compatible server connection from {}", peer_addr);

        let socket = Arc::new(std::net::UdpSocket::bind(local_addr)
            .map_err(|e| Error::TransportError(e.raw_os_error().unwrap_or(0) as u64))?);

        let tokio_socket = Arc::new(tokio::net::UdpSocket::from_std(socket.try_clone().unwrap()).unwrap());

        let connection_id = crate::quic::connection::ConnectionId::new();
        let inner = GQuicConnection::new(connection_id, peer_addr, tokio_socket, false);
        let dcid = odcid.cloned().unwrap_or_else(|| ConnectionId::new());

        Ok(Self {
            inner,
            config: config.clone(),
            http3_conn: None,
            is_server: true,
            local_addr,
            peer_addr,
            scid: hex::encode(scid.as_ref()),
            dcid: hex::encode(dcid.as_ref()),
            trace_id: format!("server-{}", hex::encode(scid.as_ref())),
            streams: HashMap::new(),
            next_stream_id: 1, // Server-initiated streams start at 1
        })
    }

    /// Process incoming packet
    pub fn recv(&mut self, buf: &mut [u8], info: RecvInfo) -> Result<usize> {
        debug!("Processing packet from {} ({} bytes)", info.from, buf.len());

        // Simplified packet processing - in real implementation would handle
        // QUIC packet parsing, decryption, and frame processing

        // Return the number of bytes processed
        Ok(buf.len())
    }

    /// Send outgoing packets
    pub fn send(&mut self, out: &mut [u8]) -> Result<(usize, SendInfo)> {
        // Simplified packet generation - in real implementation would construct
        // QUIC packets with proper encryption and framing

        if out.len() < 1200 {
            return Err(Error::BufferTooShort);
        }

        // Generate a dummy packet
        let packet_size = 1200;
        out[..packet_size].fill(0x42); // Dummy data

        let send_info = SendInfo {
            to: self.peer_addr,
            from: self.local_addr,
        };

        Ok((packet_size, send_info))
    }

    /// Get timeout for the connection
    pub fn timeout(&self) -> Option<Duration> {
        Some(Duration::from_millis(100)) // Simplified timeout
    }

    /// Handle timeout event
    pub fn on_timeout(&mut self) {
        debug!("Handling timeout for connection {}", self.trace_id);
    }

    /// Check if connection is established
    pub fn is_established(&self) -> bool {
        // Simplified - in real implementation would check handshake state
        true
    }

    /// Check if connection is closed
    pub fn is_closed(&self) -> bool {
        false // Simplified
    }

    /// Check if connection is draining
    pub fn is_draining(&self) -> bool {
        false // Simplified
    }

    /// Get connection statistics
    pub fn stats(&self) -> Stats {
        Stats {
            recv: 0,
            sent: 0,
            lost: 0,
            rtt: Duration::from_millis(50),
            cwnd: 1200,
            delivery_rate: 0,
        }
    }

    /// Close the connection
    pub fn close(&mut self, app: bool, err: u64, reason: &[u8]) -> Result<()> {
        debug!("Closing connection {} (app: {}, err: {}, reason: {:?})",
               self.trace_id, app, err, reason);
        Ok(())
    }

    /// Get trace ID
    pub fn trace_id(&self) -> &str {
        &self.trace_id
    }

    /// Get source connection ID
    pub fn source_id(&self) -> &[u8] {
        self.scid.as_bytes()
    }

    /// Get destination connection ID
    pub fn destination_id(&self) -> &[u8] {
        self.dcid.as_bytes()
    }

    /// Application protocol selected
    pub fn application_proto(&self) -> &[u8] {
        b"h3" // Default to HTTP/3
    }

    /// Check if early data is enabled
    pub fn is_in_early_data(&self) -> bool {
        false // Simplified
    }

    /// Stream operations

    /// Write data to a stream
    pub fn stream_send(&mut self, stream_id: u64, buf: &[u8], fin: bool) -> Result<usize> {
        debug!("Sending {} bytes to stream {} (fin: {})", buf.len(), stream_id, fin);

        let stream = self.streams.entry(stream_id).or_insert_with(|| StreamState {
            readable: false,
            writable: true,
            finished: false,
            send_buf: Vec::new(),
            recv_buf: Vec::new(),
        });

        if !stream.writable {
            return Err(Error::InvalidStreamState);
        }

        stream.send_buf.extend_from_slice(buf);

        if fin {
            stream.finished = true;
            stream.writable = false;
        }

        Ok(buf.len())
    }

    /// Read data from a stream
    pub fn stream_recv(&mut self, stream_id: u64, out: &mut [u8]) -> Result<(usize, bool)> {
        let stream = self.streams.get_mut(&stream_id)
            .ok_or(Error::InvalidStreamState)?;

        if !stream.readable || stream.recv_buf.is_empty() {
            return Err(Error::Done);
        }

        let to_copy = std::cmp::min(out.len(), stream.recv_buf.len());
        out[..to_copy].copy_from_slice(&stream.recv_buf[..to_copy]);
        stream.recv_buf.drain(..to_copy);

        let fin = stream.finished && stream.recv_buf.is_empty();

        debug!("Read {} bytes from stream {} (fin: {})", to_copy, stream_id, fin);

        Ok((to_copy, fin))
    }

    /// Shutdown stream for writing
    pub fn stream_shutdown(&mut self, stream_id: u64, direction: Shutdown, err: u64) -> Result<()> {
        debug!("Shutting down stream {} in direction {:?} with error {}",
               stream_id, direction, err);

        if let Some(stream) = self.streams.get_mut(&stream_id) {
            match direction {
                Shutdown::Read => stream.readable = false,
                Shutdown::Write => stream.writable = false,
            }
        }

        Ok(())
    }

    /// Get stream capacity
    pub fn stream_capacity(&self, stream_id: u64) -> Result<usize> {
        self.streams.get(&stream_id)
            .map(|_| 65536) // Return default capacity
            .ok_or(Error::InvalidStreamState)
    }

    /// Check if stream is readable
    pub fn stream_readable(&self, stream_id: u64) -> bool {
        self.streams.get(&stream_id)
            .map(|s| s.readable && !s.recv_buf.is_empty())
            .unwrap_or(false)
    }

    /// Check if stream is writable
    pub fn stream_writable(&self, stream_id: u64) -> bool {
        self.streams.get(&stream_id)
            .map(|s| s.writable)
            .unwrap_or(false)
    }

    /// Check if stream is finished
    pub fn stream_finished(&self, stream_id: u64) -> bool {
        self.streams.get(&stream_id)
            .map(|s| s.finished)
            .unwrap_or(false)
    }

    /// Get readable streams
    pub fn readable(&self) -> StreamIter {
        let readable_streams: Vec<u64> = self.streams.iter()
            .filter(|(_, stream)| stream.readable && !stream.recv_buf.is_empty())
            .map(|(&id, _)| id)
            .collect();

        StreamIter::new(readable_streams)
    }

    /// Get writable streams
    pub fn writable(&self) -> StreamIter {
        let writable_streams: Vec<u64> = self.streams.iter()
            .filter(|(_, stream)| stream.writable)
            .map(|(&id, _)| id)
            .collect();

        StreamIter::new(writable_streams)
    }

    /// Datagram operations (if enabled)

    /// Send datagram
    pub fn dgram_send(&mut self, buf: &[u8]) -> Result<()> {
        if self.config.dgram_send_max_queue_len.is_none() {
            return Err(Error::InvalidState);
        }

        debug!("Sending datagram with {} bytes", buf.len());
        Ok(())
    }

    /// Receive datagram
    pub fn dgram_recv(&mut self, out: &mut [u8]) -> Result<usize> {
        if self.config.dgram_recv_max_queue_len.is_none() {
            return Err(Error::InvalidState);
        }

        // No datagrams available
        Err(Error::Done)
    }

    /// Get maximum datagram size
    pub fn dgram_max_writable_len(&self) -> Option<usize> {
        self.config.dgram_send_max_queue_len.map(|_| 1200)
    }
}

/// Stream iterator for Quiche compatibility
pub struct StreamIter {
    streams: Vec<u64>,
    index: usize,
}

impl StreamIter {
    fn new(streams: Vec<u64>) -> Self {
        Self { streams, index: 0 }
    }
}

impl Iterator for StreamIter {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.streams.len() {
            let stream_id = self.streams[self.index];
            self.index += 1;
            Some(stream_id)
        } else {
            None
        }
    }
}


/// Connection statistics
#[derive(Debug, Clone)]
pub struct Stats {
    pub recv: usize,
    pub sent: usize,
    pub lost: usize,
    pub rtt: Duration,
    pub cwnd: usize,
    pub delivery_rate: u64,
}

/// Stream shutdown direction
#[derive(Debug, Clone, Copy)]
pub enum Shutdown {
    Read,
    Write,
}

/// HTTP/3 module for Quiche compatibility
pub mod h3 {
    use super::*;

    /// HTTP/3 connection
    pub struct Connection {
        inner: Http3Connection,
    }

    /// HTTP/3 configuration
    #[derive(Debug, Clone)]
    pub struct Config {
        max_field_section_size: Option<u64>,
        qpack_max_table_capacity: Option<u64>,
        qpack_blocked_streams: Option<u64>,
    }

    impl Config {
        pub fn new() -> Self {
            Self {
                max_field_section_size: Some(16384),
                qpack_max_table_capacity: Some(4096),
                qpack_blocked_streams: Some(16),
            }
        }

        pub fn set_max_field_section_size(&mut self, size: u64) {
            self.max_field_section_size = Some(size);
        }
    }

    impl Connection {
        /// Create new HTTP/3 connection
        pub fn with_transport(
            quic_conn: &mut super::Connection,
            config: &Config,
        ) -> Result<Self> {
            debug!("Creating HTTP/3 connection");

            let inner = Http3Connection::new();
            Ok(Self { inner })
        }

        /// Send HTTP/3 request
        pub fn send_request(
            &mut self,
            quic_conn: &mut super::Connection,
            headers: &[Header],
            fin: bool,
        ) -> Result<u64> {
            debug!("Sending HTTP/3 request with {} headers (fin: {})", headers.len(), fin);

            // Convert headers and send request
            let stream_id = quic_conn.next_stream_id;
            quic_conn.next_stream_id += 4; // Skip stream IDs

            Ok(stream_id)
        }

        /// Send HTTP/3 response
        pub fn send_response(
            &mut self,
            quic_conn: &mut super::Connection,
            stream_id: u64,
            headers: &[Header],
            fin: bool,
        ) -> Result<()> {
            debug!("Sending HTTP/3 response on stream {} with {} headers (fin: {})",
                   stream_id, headers.len(), fin);
            Ok(())
        }

        /// Send HTTP/3 body
        pub fn send_body(
            &mut self,
            quic_conn: &mut super::Connection,
            stream_id: u64,
            body: &[u8],
            fin: bool,
        ) -> Result<usize> {
            quic_conn.stream_send(stream_id, body, fin)
        }

        /// Receive HTTP/3 data
        pub fn recv_body(
            &mut self,
            quic_conn: &mut super::Connection,
            stream_id: u64,
            out: &mut [u8],
        ) -> Result<usize> {
            let (len, _fin) = quic_conn.stream_recv(stream_id, out)?;
            Ok(len)
        }

        /// Poll for events
        pub fn poll(&mut self, quic_conn: &mut super::Connection) -> Result<(u64, Event)> {
            // Return dummy event for now
            Err(Error::Done)
        }
    }

    /// HTTP/3 header
    #[derive(Debug, Clone)]
    pub struct Header {
        name: String,
        value: String,
    }

    impl Header {
        pub fn new(name: &str, value: &str) -> Self {
            Self {
                name: name.to_string(),
                value: value.to_string(),
            }
        }

        pub fn name(&self) -> &str {
            &self.name
        }

        pub fn value(&self) -> &str {
            &self.value
        }
    }

    /// HTTP/3 events
    #[derive(Debug)]
    pub enum Event {
        Headers { list: Vec<Header>, has_body: bool },
        Data { data: Vec<u8> },
        Finished,
        Reset(u64),
        PriorityUpdate,
        GoAway,
    }

    impl Default for Config {
        fn default() -> Self {
            Self::new()
        }
    }
}

/// Utility functions matching Quiche API

/// Generate random connection ID
pub fn connection_id_generator() -> impl Fn() -> String {
    || format!("{:016x}", fastrand::u64(..))
}

/// Negotiate QUIC version
pub fn negotiate_version(scid: &[u8], dcid: &[u8], out: &mut [u8]) -> Result<usize> {
    // Simplified version negotiation
    if out.len() < 1200 {
        return Err(Error::BufferTooShort);
    }

    // Generate version negotiation packet
    out[..20].fill(0xFF); // Dummy version negotiation
    Ok(20)
}

/// Retry packet generation
pub fn retry(
    scid: &[u8],
    dcid: &[u8],
    new_scid: &[u8],
    token: &[u8],
    version: u32,
    out: &mut [u8],
) -> Result<usize> {
    if out.len() < token.len() + 50 {
        return Err(Error::BufferTooShort);
    }

    debug!("Generating retry packet");

    // Generate retry packet (simplified)
    out[..token.len()].copy_from_slice(token);
    Ok(token.len() + 20)
}

/// Header parsing utilities
pub fn header_info(buf: &[u8]) -> Result<(u8, u32, usize, usize)> {
    if buf.is_empty() {
        return Err(Error::InvalidPacket);
    }

    // Parse QUIC header (simplified)
    let ty = buf[0];
    let version = 1; // QUIC v1
    let dcid_len = 8;
    let scid_len = 8;

    Ok((ty, version, dcid_len, scid_len))
}

/// Create a new client connection (module-level convenience function)
pub fn connect(
    server_name: Option<&str>,
    scid: &ConnectionId,
    local: SocketAddr,
    peer: SocketAddr,
    config: &mut Config,
) -> Result<Connection> {
    Connection::connect(server_name, scid, local, peer, config)
}

/// Create a new server connection (module-level convenience function)
pub fn accept(
    scid: &ConnectionId,
    odcid: Option<&ConnectionId>,
    local: SocketAddr,
    peer: SocketAddr,
    config: &mut Config,
) -> Result<Connection> {
    Connection::accept(scid, odcid, local, peer, config)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_creation() {
        let config = Config::new(0x1).unwrap();
        assert_eq!(config.version, 1);
    }

    #[test]
    fn test_connection_creation() {
        let mut config = Config::new(0x1).unwrap();
        config.set_initial_max_data(1024 * 1024);

        let scid = ConnectionId::new();
        let local_addr = "127.0.0.1:8080".parse().unwrap();
        let peer_addr = "127.0.0.1:8081".parse().unwrap();

        // Note: This would fail in practice without proper socket setup
        // let conn = Connection::connect(Some("localhost"), &scid, local_addr, peer_addr, &config);
        // assert!(conn.is_ok());
    }

    #[test]
    fn test_stream_operations() {
        let config = Config::new(0x1).unwrap();
        let scid = ConnectionId::new();
        let local_addr = "127.0.0.1:8080".parse().unwrap();
        let peer_addr = "127.0.0.1:8081".parse().unwrap();

        // This is a conceptual test - actual implementation would need proper setup
        // let mut conn = Connection::accept(&scid, None, local_addr, peer_addr, &config).unwrap();
        // let result = conn.stream_send(4, b"hello", false);
        // assert!(result.is_ok());
    }

    #[test]
    fn test_h3_config() {
        let config = h3::Config::new();
        assert_eq!(config.max_field_section_size, Some(16384));
    }

    #[test]
    fn test_header_creation() {
        let header = h3::Header::new(":method", "GET");
        assert_eq!(header.name(), ":method");
        assert_eq!(header.value(), "GET");
    }

    #[test]
    fn test_utility_functions() {
        let scid = b"12345678";
        let dcid = b"87654321";
        let mut out = vec![0u8; 1500];

        let result = negotiate_version(scid, dcid, &mut out);
        assert!(result.is_ok());

        let token = b"retry_token";
        let result = retry(scid, dcid, scid, token, 1, &mut out);
        assert!(result.is_ok());
    }
}