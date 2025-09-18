//! WebTransport Protocol Implementation
//!
//! WebTransport provides bidirectional, multiplexed, reliable/unreliable transport
//! over HTTP/3. It enables web applications to use QUIC streams and datagrams.

use crate::{QuicError, QuicResult, Connection, ConnectionId};
use crate::http3::Http3Connection;
use bytes::{Bytes, BytesMut, BufMut, Buf};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
use std::net::SocketAddr;
use std::time::Duration;

/// WebTransport session over HTTP/3
pub struct WebTransportSession {
    session_id: u64,
    quic_conn: Arc<crate::quic::connection::Connection>,
    http3_conn: Arc<Http3Connection>,
    streams: Arc<Mutex<HashMap<u64, WebTransportStream>>>,
    datagram_tx: mpsc::Sender<Bytes>,
    datagram_rx: mpsc::Receiver<Bytes>,
    state: SessionState,
    config: WebTransportConfig,
}

/// WebTransport configuration
#[derive(Debug, Clone)]
pub struct WebTransportConfig {
    /// Maximum number of concurrent streams
    pub max_concurrent_streams: u32,
    /// Enable datagram support
    pub enable_datagrams: bool,
    /// Session idle timeout
    pub idle_timeout: Duration,
    /// Maximum datagram size
    pub max_datagram_size: usize,
    /// Enable reliable streams
    pub enable_reliable_streams: bool,
    /// Enable unreliable streams
    pub enable_unreliable_streams: bool,
}

impl Default for WebTransportConfig {
    fn default() -> Self {
        Self {
            max_concurrent_streams: 100,
            enable_datagrams: true,
            idle_timeout: Duration::from_secs(30),
            max_datagram_size: 1200,
            enable_reliable_streams: true,
            enable_unreliable_streams: true,
        }
    }
}

/// WebTransport session state
#[derive(Debug, Clone, PartialEq)]
pub enum SessionState {
    Connecting,
    Connected,
    Draining,
    Closed,
}

/// WebTransport stream
pub struct WebTransportStream {
    stream_id: u64,
    stream_type: StreamType,
    send_buf: BytesMut,
    recv_buf: BytesMut,
    state: StreamState,
}

/// Stream type for WebTransport
#[derive(Debug, Clone, PartialEq)]
pub enum StreamType {
    Bidirectional,
    UnidirectionalSend,
    UnidirectionalReceive,
}

/// Stream state
#[derive(Debug, Clone, PartialEq)]
pub enum StreamState {
    Open,
    SendClosed,
    RecvClosed,
    Closed,
}

impl WebTransportSession {
    /// Create a new WebTransport session
    pub async fn new(
        quic_conn: Arc<crate::quic::connection::Connection>,
        http3_conn: Arc<Http3Connection>,
        config: WebTransportConfig,
    ) -> QuicResult<Self> {
        let (datagram_tx, datagram_rx) = mpsc::channel(1024);

        Ok(Self {
            session_id: rand::random(),
            quic_conn,
            http3_conn,
            streams: Arc::new(Mutex::new(HashMap::new())),
            datagram_tx,
            datagram_rx,
            state: SessionState::Connecting,
            config,
        })
    }

    /// Connect WebTransport session
    pub async fn connect(&mut self, url: &str) -> QuicResult<()> {
        // Send CONNECT request with :protocol = "webtransport"
        let headers = vec![
            (":method".to_string(), "CONNECT".to_string()),
            (":protocol".to_string(), "webtransport".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":path".to_string(), url.to_string()),
            ("sec-webtransport-http3-draft".to_string(), "draft02".to_string()),
        ];

        // Create HTTP/3 stream for CONNECT (simplified for now)
        let _stream_id = self.quic_conn.open_stream(false).await?; // unidirectional for request

        // Simplified: assume connection successful for now
        // In a real implementation, this would send CONNECT headers and wait for 200 response

        self.state = SessionState::Connected;
        Ok(())
    }

    /// Create a bidirectional stream
    pub async fn create_bidirectional_stream(&self) -> QuicResult<WebTransportStream> {
        if self.state != SessionState::Connected {
            return Err(QuicError::InvalidState("Session not connected".to_string()));
        }

        let stream_id = self.quic_conn.open_stream(true).await?; // bidirectional

        let stream = WebTransportStream {
            stream_id: stream_id.value(),
            stream_type: StreamType::Bidirectional,
            send_buf: BytesMut::with_capacity(65536),
            recv_buf: BytesMut::with_capacity(65536),
            state: StreamState::Open,
        };

        let mut streams = self.streams.lock().await;
        streams.insert(stream_id.value(), stream.clone());

        Ok(stream)
    }

    /// Create a unidirectional send stream
    pub async fn create_unidirectional_stream(&self) -> QuicResult<WebTransportStream> {
        if self.state != SessionState::Connected {
            return Err(QuicError::InvalidState("Session not connected".to_string()));
        }

        let stream_id = self.quic_conn.open_stream(false).await?; // unidirectional

        let stream = WebTransportStream {
            stream_id: stream_id.value(),
            stream_type: StreamType::UnidirectionalSend,
            send_buf: BytesMut::with_capacity(65536),
            recv_buf: BytesMut::new(),
            state: StreamState::Open,
        };

        let mut streams = self.streams.lock().await;
        streams.insert(stream_id.value(), stream.clone());

        Ok(stream)
    }

    /// Accept an incoming stream
    pub async fn accept_stream(&self) -> QuicResult<WebTransportStream> {
        // For now, simulate accepting a bidirectional stream
        let stream_id = self.quic_conn.open_stream(true).await?;
        let wt_type = StreamType::Bidirectional; // Simplified for now

        let stream = WebTransportStream {
            stream_id: stream_id.value(),
            stream_type: wt_type,
            send_buf: BytesMut::with_capacity(65536),
            recv_buf: BytesMut::with_capacity(65536),
            state: StreamState::Open,
        };

        let mut streams = self.streams.lock().await;
        streams.insert(stream_id.value(), stream.clone());

        Ok(stream)
    }

    /// Send a datagram
    pub async fn send_datagram(&self, data: &[u8]) -> QuicResult<()> {
        if !self.config.enable_datagrams {
            return Err(QuicError::Protocol("Datagrams not enabled".into()));
        }

        if data.len() > self.config.max_datagram_size {
            return Err(QuicError::Protocol("Datagram too large".into()));
        }

        // Encode WebTransport datagram with session ID
        let mut buf = BytesMut::with_capacity(data.len() + 8);
        buf.put_u64(self.session_id);
        buf.put_slice(data);

        // Send via datagram channel (simulated for now)
        self.datagram_tx.send(buf.freeze()).await
            .map_err(|_| QuicError::Protocol("Failed to send datagram".into()))?;
        Ok(())
    }

    /// Receive a datagram
    pub async fn recv_datagram(&mut self) -> QuicResult<Bytes> {
        if !self.config.enable_datagrams {
            return Err(QuicError::Protocol("Datagrams not enabled".into()));
        }

        self.datagram_rx.recv().await
            .ok_or(QuicError::Protocol("No datagram available".into()))
    }

    /// Close the session
    pub async fn close(&mut self, code: u32, reason: &str) -> QuicResult<()> {
        self.state = SessionState::Draining;

        // Send CLOSE_WEBTRANSPORT_SESSION capsule
        let mut capsule = BytesMut::new();
        capsule.put_u64(0x2843); // Capsule type
        capsule.put_u32(code);
        capsule.put_u32(reason.len() as u32);
        capsule.put_slice(reason.as_bytes());

        // Send close capsule via datagram channel (simplified)
        self.datagram_tx.send(capsule.freeze()).await
            .map_err(|_| QuicError::Protocol("Failed to send close capsule".into()))?;

        self.state = SessionState::Closed;
        Ok(())
    }

    /// Get session statistics
    pub fn stats(&self) -> SessionStats {
        SessionStats {
            session_id: self.session_id,
            state: self.state.clone(),
            active_streams: self.streams.try_lock()
                .map(|s| s.len())
                .unwrap_or(0),
        }
    }
}

impl WebTransportStream {
    /// Send data on the stream
    pub async fn send(&mut self, data: &[u8]) -> QuicResult<usize> {
        if self.state == StreamState::SendClosed || self.state == StreamState::Closed {
            return Err(QuicError::InvalidState("Session not connected".to_string()));
        }

        self.send_buf.put_slice(data);
        Ok(data.len())
    }

    /// Receive data from the stream
    pub async fn recv(&mut self, buf: &mut [u8]) -> QuicResult<usize> {
        if self.state == StreamState::RecvClosed || self.state == StreamState::Closed {
            return Err(QuicError::InvalidState("Session not connected".to_string()));
        }

        let len = std::cmp::min(buf.len(), self.recv_buf.len());
        if len > 0 {
            buf[..len].copy_from_slice(&self.recv_buf[..len]);
            self.recv_buf.advance(len);
        }
        Ok(len)
    }

    /// Close the send side of the stream
    pub fn close_send(&mut self) {
        match self.state {
            StreamState::Open => self.state = StreamState::SendClosed,
            StreamState::RecvClosed => self.state = StreamState::Closed,
            _ => {}
        }
    }

    /// Close the receive side of the stream
    pub fn close_recv(&mut self) {
        match self.state {
            StreamState::Open => self.state = StreamState::RecvClosed,
            StreamState::SendClosed => self.state = StreamState::Closed,
            _ => {}
        }
    }

    /// Get stream ID
    pub fn id(&self) -> u64 {
        self.stream_id
    }
}

impl Clone for WebTransportStream {
    fn clone(&self) -> Self {
        Self {
            stream_id: self.stream_id,
            stream_type: self.stream_type.clone(),
            send_buf: BytesMut::new(),
            recv_buf: BytesMut::new(),
            state: self.state.clone(),
        }
    }
}

/// WebTransport client
pub struct WebTransportClient {
    endpoint: SocketAddr,
    sessions: Arc<Mutex<HashMap<u64, Arc<WebTransportSession>>>>,
    config: WebTransportConfig,
}

impl WebTransportClient {
    /// Create a new WebTransport client
    pub fn new(endpoint: SocketAddr, config: WebTransportConfig) -> Self {
        Self {
            endpoint,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            config,
        }
    }

    /// Connect to a WebTransport server
    pub async fn connect(&self, url: &str) -> QuicResult<Arc<WebTransportSession>> {
        // Create HTTP/3 connection (simplified)
        let http3_conn = Arc::new(Http3Connection::new());

        // Create WebTransport session (using placeholder QUIC connection)
        let quic_conn = Arc::new(crate::quic::connection::Connection::new(
            crate::quic::connection::ConnectionId::new(),
            std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
            Arc::new(tokio::net::UdpSocket::bind("0.0.0.0:0").await?),
            true, // is_client
        ));
        let mut session = WebTransportSession::new(
            quic_conn,
            http3_conn,
            self.config.clone()
        ).await?;

        // Perform WebTransport handshake
        session.connect(url).await?;

        let session = Arc::new(session);
        let mut sessions = self.sessions.lock().await;
        sessions.insert(session.session_id, session.clone());

        Ok(session)
    }
}

/// WebTransport server
pub struct WebTransportServer {
    endpoint: SocketAddr,
    sessions: Arc<Mutex<HashMap<u64, Arc<WebTransportSession>>>>,
    config: WebTransportConfig,
}

impl WebTransportServer {
    /// Create a new WebTransport server
    pub fn new(endpoint: SocketAddr, config: WebTransportConfig) -> Self {
        Self {
            endpoint,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            config,
        }
    }

    /// Accept WebTransport sessions
    pub async fn accept(&self) -> QuicResult<Arc<WebTransportSession>> {
        // Accept HTTP/3 connection (simplified)
        let http3_conn = Arc::new(Http3Connection::new());

        // Create QUIC connection for server
        let quic_conn = Arc::new(crate::quic::connection::Connection::new(
            crate::quic::connection::ConnectionId::new(),
            self.endpoint,
            Arc::new(tokio::net::UdpSocket::bind(self.endpoint).await?),
            false, // is_client = false (this is a server)
        ));

        // Create WebTransport session
        let session = WebTransportSession::new(
            quic_conn,
            http3_conn,
            self.config.clone()
        ).await?;

        let session = Arc::new(session);
        let mut sessions = self.sessions.lock().await;
        sessions.insert(session.session_id, session.clone());

        Ok(session)
    }
}

/// Session statistics
#[derive(Debug)]
pub struct SessionStats {
    pub session_id: u64,
    pub state: SessionState,
    pub active_streams: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_webtransport_config() {
        let config = WebTransportConfig::default();
        assert_eq!(config.max_concurrent_streams, 100);
        assert!(config.enable_datagrams);
    }

    #[tokio::test]
    async fn test_stream_state_transitions() {
        let mut stream = WebTransportStream {
            stream_id: 1,
            stream_type: StreamType::Bidirectional,
            send_buf: BytesMut::new(),
            recv_buf: BytesMut::new(),
            state: StreamState::Open,
        };

        stream.close_send();
        assert_eq!(stream.state, StreamState::SendClosed);

        stream.close_recv();
        assert_eq!(stream.state, StreamState::Closed);
    }
}