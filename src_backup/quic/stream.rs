use bytes::{Bytes, BytesMut};
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, Notify};
use tokio::io::{AsyncRead, AsyncWrite};
use std::pin::Pin;
use std::task::{Context, Poll};
use serde::{Serialize, Deserialize};

/// QUIC stream identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct StreamId(u64);

impl StreamId {
    pub fn new(id: u64) -> Self {
        Self(id)
    }
    
    pub fn value(&self) -> u64 {
        self.0
    }
    
    pub fn is_bidirectional(&self) -> bool {
        (self.0 & 0x02) == 0
    }
    
    pub fn is_client_initiated(&self) -> bool {
        (self.0 & 0x01) == 0
    }
    
    pub fn next_bidirectional(&self) -> Self {
        Self(self.0 + 4)
    }
    
    pub fn next_unidirectional(&self) -> Self {
        Self(self.0 + 4)
    }
}

impl std::fmt::Display for StreamId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Stream state for flow control and ordering
#[derive(Debug)]
struct StreamState {
    send_offset: u64,
    recv_offset: u64,
    max_stream_data: u64,
    recv_buffer: VecDeque<(u64, Bytes)>, // (offset, data) pairs
    fin_received: bool,
    fin_sent: bool,
    reset: bool,
}

impl StreamState {
    fn new() -> Self {
        Self {
            send_offset: 0,
            recv_offset: 0,
            max_stream_data: 1024 * 1024, // 1MB default
            recv_buffer: VecDeque::new(),
            fin_received: false,
            fin_sent: false,
            reset: false,
        }
    }
}

/// Bidirectional QUIC stream
#[derive(Debug)]
pub struct BiStream {
    stream_id: StreamId,
    state: Arc<Mutex<StreamState>>,
    send_tx: mpsc::UnboundedSender<(Bytes, bool)>, // (data, fin)
    recv_rx: Arc<Mutex<mpsc::UnboundedReceiver<Bytes>>>,
    notify: Arc<Notify>,
}

impl BiStream {
    pub fn new(stream_id: StreamId) -> (Self, BiStreamHandle) {
        let (send_tx, send_rx) = mpsc::unbounded_channel();
        let (recv_tx, recv_rx) = mpsc::unbounded_channel();
        let state = Arc::new(Mutex::new(StreamState::new()));
        let notify = Arc::new(Notify::new());
        
        let stream = Self {
            stream_id,
            state: Arc::clone(&state),
            send_tx,
            recv_rx: Arc::new(Mutex::new(recv_rx)),
            notify: Arc::clone(&notify),
        };
        
        let handle = BiStreamHandle {
            stream_id,
            state,
            send_rx: Arc::new(Mutex::new(send_rx)),
            recv_tx,
            notify,
        };
        
        (stream, handle)
    }
    
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }
    
    pub async fn write_all(&self, data: &[u8]) -> Result<(), super::error::StreamError> {
        let bytes = Bytes::copy_from_slice(data);
        self.send_tx
            .send((bytes, false))
            .map_err(|_| super::error::StreamError::Closed)?;
        Ok(())
    }
    
    pub async fn write_all_and_finish(&self, data: &[u8]) -> Result<(), super::error::StreamError> {
        let bytes = Bytes::copy_from_slice(data);
        self.send_tx
            .send((bytes, true))
            .map_err(|_| super::error::StreamError::Closed)?;
        Ok(())
    }
    
    pub async fn finish(&self) -> Result<(), super::error::StreamError> {
        self.send_tx
            .send((Bytes::new(), true))
            .map_err(|_| super::error::StreamError::Closed)?;
        Ok(())
    }
    
    pub async fn read_to_end(&self, max_size: usize) -> Result<Vec<u8>, super::error::StreamError> {
        let mut buffer = Vec::new();
        let mut recv_rx = self.recv_rx.lock().await;
        
        while let Some(chunk) = recv_rx.recv().await {
            buffer.extend_from_slice(&chunk);
            if buffer.len() >= max_size {
                break;
            }
        }
        
        Ok(buffer)
    }
    
    pub async fn read_chunk(&self) -> Result<Option<Bytes>, super::error::StreamError> {
        let mut recv_rx = self.recv_rx.lock().await;
        Ok(recv_rx.recv().await)
    }
}

impl AsyncRead for BiStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Simplified implementation - in production would need proper buffering
        Poll::Pending
    }
}

impl AsyncWrite for BiStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        // Simplified implementation
        Poll::Ready(Ok(buf.len()))
    }
    
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }
    
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }
}

/// Handle for managing a bidirectional stream from the connection side
#[derive(Debug)]
pub struct BiStreamHandle {
    stream_id: StreamId,
    state: Arc<Mutex<StreamState>>,
    send_rx: Arc<Mutex<mpsc::UnboundedReceiver<(Bytes, bool)>>>,
    recv_tx: mpsc::UnboundedSender<Bytes>,
    notify: Arc<Notify>,
}

impl BiStreamHandle {
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }
    
    pub async fn poll_send(&self) -> Option<(Bytes, bool)> {
        let mut send_rx = self.send_rx.lock().await;
        send_rx.recv().await
    }
    
    pub async fn deliver_data(&self, data: Bytes) -> Result<(), super::error::StreamError> {
        self.recv_tx
            .send(data)
            .map_err(|_| super::error::StreamError::Closed)?;
        self.notify.notify_one();
        Ok(())
    }
}

/// Unidirectional QUIC stream
#[derive(Debug)]
pub struct UniStream {
    stream_id: StreamId,
    state: Arc<Mutex<StreamState>>,
    send_tx: mpsc::UnboundedSender<(Bytes, bool)>,
    notify: Arc<Notify>,
}

impl UniStream {
    pub fn new(stream_id: StreamId) -> (Self, UniStreamHandle) {
        let (send_tx, send_rx) = mpsc::unbounded_channel();
        let state = Arc::new(Mutex::new(StreamState::new()));
        let notify = Arc::new(Notify::new());
        
        let stream = Self {
            stream_id,
            state: Arc::clone(&state),
            send_tx,
            notify: Arc::clone(&notify),
        };
        
        let handle = UniStreamHandle {
            stream_id,
            state,
            send_rx: Arc::new(Mutex::new(send_rx)),
            notify,
        };
        
        (stream, handle)
    }
    
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }
    
    pub async fn write_all(&self, data: &[u8]) -> Result<(), super::error::StreamError> {
        let bytes = Bytes::copy_from_slice(data);
        self.send_tx
            .send((bytes, false))
            .map_err(|_| super::error::StreamError::Closed)?;
        Ok(())
    }
    
    pub async fn finish(&self) -> Result<(), super::error::StreamError> {
        self.send_tx
            .send((Bytes::new(), true))
            .map_err(|_| super::error::StreamError::Closed)?;
        Ok(())
    }
}

impl AsyncWrite for UniStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Poll::Ready(Ok(buf.len()))
    }
    
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }
    
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }
}

/// Handle for managing a unidirectional stream
#[derive(Debug)]
pub struct UniStreamHandle {
    stream_id: StreamId,
    state: Arc<Mutex<StreamState>>,
    send_rx: Arc<Mutex<mpsc::UnboundedReceiver<(Bytes, bool)>>>,
    notify: Arc<Notify>,
}

impl UniStreamHandle {
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }
    
    pub async fn poll_send(&self) -> Option<(Bytes, bool)> {
        let mut send_rx = self.send_rx.lock().await;
        send_rx.recv().await
    }
}

// Type aliases for API compatibility
pub type StreamWriter = BiStream;
pub type StreamReader = BiStream;
pub type SendStream = UniStream;
pub type RecvStream = BiStream;