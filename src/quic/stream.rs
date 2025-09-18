//! QUIC stream implementation
//!
//! This module provides bidirectional and unidirectional stream implementations
//! for QUIC connections with proper flow control and state management.

use crate::quic::error::{QuicError, Result, StreamError};
use bytes::{Bytes, BytesMut};
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, warn};

/// Stream identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct StreamId(u64);

impl StreamId {
    /// Create a new stream ID
    pub fn new(id: u64) -> Self {
        Self(id)
    }
    
    /// Get the raw value
    pub fn value(&self) -> u64 {
        self.0
    }
    
    /// Check if this is a client-initiated stream
    pub fn is_client_initiated(&self) -> bool {
        (self.0 & 0x1) == 0
    }
    
    /// Check if this is a server-initiated stream
    pub fn is_server_initiated(&self) -> bool {
        (self.0 & 0x1) == 1
    }
    
    /// Check if this is a bidirectional stream
    pub fn is_bidirectional(&self) -> bool {
        (self.0 & 0x2) == 0
    }
    
    /// Check if this is a unidirectional stream
    pub fn is_unidirectional(&self) -> bool {
        (self.0 & 0x2) == 2
    }
}

impl std::fmt::Display for StreamId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Stream state for flow control and ordering
#[derive(Debug, Clone, PartialEq)]
pub enum StreamState {
    /// Stream is ready for data
    Ready,
    /// Stream is sending data
    Send,
    /// Stream is receiving data
    Recv,
    /// Stream has been reset by peer
    ResetRecv,
    /// Stream has been reset locally
    ResetSent,
    /// Stream is closed
    Closed,
}

/// Stream data with offset
#[derive(Debug, Clone)]
pub struct StreamData {
    /// Data offset in the stream
    pub offset: u64,
    /// Data bytes
    pub data: Bytes,
    /// Whether this is the final data chunk
    pub fin: bool,
}

/// Bidirectional stream
pub struct BiStream {
    /// Stream identifier
    id: StreamId,
    /// Send side state
    send_state: Arc<RwLock<StreamState>>,
    /// Receive side state
    recv_state: Arc<RwLock<StreamState>>,
    /// Send buffer
    send_buffer: Arc<Mutex<BytesMut>>,
    /// Receive buffer
    recv_buffer: Arc<Mutex<VecDeque<StreamData>>>,
    /// Send channel to connection
    send_tx: mpsc::UnboundedSender<StreamData>,
    /// Receive channel from connection
    recv_rx: Arc<Mutex<mpsc::UnboundedReceiver<StreamData>>>,
    /// Flow control window
    flow_control_window: Arc<RwLock<u64>>,
    /// Next expected offset
    next_offset: Arc<RwLock<u64>>,
    /// Whether stream is finished
    finished: Arc<RwLock<bool>>,
}

/// Unidirectional stream
pub struct UniStream {
    /// Stream identifier
    id: StreamId,
    /// Stream state
    state: Arc<RwLock<StreamState>>,
    /// Send buffer (for send-only streams)
    send_buffer: Arc<Mutex<BytesMut>>,
    /// Receive buffer (for receive-only streams)
    recv_buffer: Arc<Mutex<VecDeque<StreamData>>>,
    /// Send channel to connection
    send_tx: Option<mpsc::UnboundedSender<StreamData>>,
    /// Receive channel from connection
    recv_rx: Option<Arc<Mutex<mpsc::UnboundedReceiver<StreamData>>>>,
    /// Flow control window
    flow_control_window: Arc<RwLock<u64>>,
    /// Next expected offset
    next_offset: Arc<RwLock<u64>>,
    /// Whether stream is finished
    finished: Arc<RwLock<bool>>,
}

/// Stream handle for connection management
#[derive(Debug)]
pub struct BiStreamHandle {
    /// Stream ID
    id: StreamId,
    /// Data sender
    data_tx: mpsc::UnboundedSender<StreamData>,
    /// Stream state
    state: Arc<RwLock<StreamState>>,
}

/// Unidirectional stream handle
#[derive(Debug)]
pub struct UniStreamHandle {
    /// Stream ID
    id: StreamId,
    /// Data sender
    data_tx: Option<mpsc::UnboundedSender<StreamData>>,
    /// Stream state
    state: Arc<RwLock<StreamState>>,
}

impl BiStream {
    /// Create a new bidirectional stream
    pub fn new(id: StreamId) -> (Self, BiStreamHandle) {
        let (send_tx, recv_rx) = mpsc::unbounded_channel();
        let (data_tx, data_rx) = mpsc::unbounded_channel();
        
        let send_state = Arc::new(RwLock::new(StreamState::Ready));
        let recv_state = Arc::new(RwLock::new(StreamState::Ready));
        
        let stream = Self {
            id,
            send_state: send_state.clone(),
            recv_state: recv_state.clone(),
            send_buffer: Arc::new(Mutex::new(BytesMut::new())),
            recv_buffer: Arc::new(Mutex::new(VecDeque::new())),
            send_tx,
            recv_rx: Arc::new(Mutex::new(data_rx)),
            flow_control_window: Arc::new(RwLock::new(65536)), // 64KB initial window
            next_offset: Arc::new(RwLock::new(0)),
            finished: Arc::new(RwLock::new(false)),
        };
        
        let handle = BiStreamHandle {
            id,
            data_tx,
            state: send_state,
        };
        
        (stream, handle)
    }
    
    /// Get stream ID
    pub fn id(&self) -> StreamId {
        self.id
    }
    
    /// Write data to the stream
    pub async fn write_all(&mut self, data: &[u8]) -> Result<()> {
        let mut send_state = self.send_state.write().await;
        if *send_state == StreamState::Closed || *send_state == StreamState::ResetSent {
            return Err(QuicError::Stream(StreamError::Closed));
        }
        
        *send_state = StreamState::Send;
        drop(send_state);
        
        let mut buffer = self.send_buffer.lock().await;
        buffer.extend_from_slice(data);
        
        // Send data to connection
        let stream_data = StreamData {
            offset: *self.next_offset.read().await,
            data: Bytes::copy_from_slice(data),
            fin: false,
        };
        
        if let Err(_) = self.send_tx.send(stream_data) {
            return Err(QuicError::Stream(StreamError::Closed));
        }
        
        // Update offset
        let mut offset = self.next_offset.write().await;
        *offset += data.len() as u64;
        
        debug!("Wrote {} bytes to stream {}", data.len(), self.id);
        Ok(())
    }
    
    /// Write data and finish the stream
    pub async fn write_all_and_finish(&mut self, data: &[u8]) -> Result<()> {
        self.write_all(data).await?;
        self.finish().await
    }
    
    /// Finish the stream (close send side)
    pub async fn finish(&mut self) -> Result<()> {
        let mut send_state = self.send_state.write().await;
        if *send_state == StreamState::Closed || *send_state == StreamState::ResetSent {
            return Err(QuicError::Stream(StreamError::Closed));
        }
        
        *send_state = StreamState::Closed;
        drop(send_state);
        
        // Send FIN
        let stream_data = StreamData {
            offset: *self.next_offset.read().await,
            data: Bytes::new(),
            fin: true,
        };
        
        if let Err(_) = self.send_tx.send(stream_data) {
            return Err(QuicError::Stream(StreamError::Closed));
        }
        
        let mut finished = self.finished.write().await;
        *finished = true;
        
        debug!("Finished stream {}", self.id);
        Ok(())
    }
    
    /// Read data from the stream
    pub async fn read_to_end(&mut self) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        
        loop {
            match self.read_chunk().await? {
                Some(chunk) => data.extend_from_slice(&chunk),
                None => break,
            }
        }
        
        Ok(data)
    }
    
    /// Read a chunk of data from the stream
    pub async fn read_chunk(&mut self) -> Result<Option<Bytes>> {
        let mut recv_rx = self.recv_rx.lock().await;
        
        if let Some(stream_data) = recv_rx.recv().await {
            let mut recv_state = self.recv_state.write().await;
            *recv_state = StreamState::Recv;
            drop(recv_state);
            
            if stream_data.fin {
                let mut recv_state = self.recv_state.write().await;
                *recv_state = StreamState::Closed;
            }
            
            debug!("Read {} bytes from stream {}", stream_data.data.len(), self.id);
            Ok(Some(stream_data.data))
        } else {
            Ok(None)
        }
    }
    
    /// Reset the stream
    pub async fn reset(&mut self, error_code: u64) -> Result<()> {
        let mut send_state = self.send_state.write().await;
        *send_state = StreamState::ResetSent;
        drop(send_state);
        
        let mut recv_state = self.recv_state.write().await;
        *recv_state = StreamState::ResetRecv;
        
        debug!("Reset stream {} with error code {}", self.id, error_code);
        Ok(())
    }
    
    /// Check if stream is finished
    pub async fn is_finished(&self) -> bool {
        *self.finished.read().await
    }
    
    /// Get stream state
    pub async fn send_state(&self) -> StreamState {
        self.send_state.read().await.clone()
    }
    
    /// Get receive state
    pub async fn recv_state(&self) -> StreamState {
        self.recv_state.read().await.clone()
    }
}

impl UniStream {
    /// Create a new unidirectional stream
    pub fn new(id: StreamId) -> (Self, UniStreamHandle) {
        let state = Arc::new(RwLock::new(StreamState::Ready));
        
        let (send_tx, data_tx) = if id.is_client_initiated() {
            // Client-initiated unidirectional stream - send only
            let (tx, _) = mpsc::unbounded_channel();
            (Some(tx), Some(mpsc::unbounded_channel().0))
        } else {
            // Server-initiated unidirectional stream - receive only
            (None, None)
        };
        
        let stream = Self {
            id,
            state: state.clone(),
            send_buffer: Arc::new(Mutex::new(BytesMut::new())),
            recv_buffer: Arc::new(Mutex::new(VecDeque::new())),
            send_tx,
            recv_rx: None,
            flow_control_window: Arc::new(RwLock::new(65536)),
            next_offset: Arc::new(RwLock::new(0)),
            finished: Arc::new(RwLock::new(false)),
        };
        
        let handle = UniStreamHandle {
            id,
            data_tx,
            state,
        };
        
        (stream, handle)
    }
    
    /// Get stream ID
    pub fn id(&self) -> StreamId {
        self.id
    }
    
    /// Write data to the stream (send-only streams)
    pub async fn write_all(&mut self, data: &[u8]) -> Result<()> {
        let send_tx = self.send_tx.as_ref()
            .ok_or(QuicError::Stream(StreamError::InvalidState))?;
        
        let mut state = self.state.write().await;
        if *state == StreamState::Closed || *state == StreamState::ResetSent {
            return Err(QuicError::Stream(StreamError::Closed));
        }
        
        *state = StreamState::Send;
        drop(state);
        
        let stream_data = StreamData {
            offset: *self.next_offset.read().await,
            data: Bytes::copy_from_slice(data),
            fin: false,
        };
        
        if let Err(_) = send_tx.send(stream_data) {
            return Err(QuicError::Stream(StreamError::Closed));
        }
        
        // Update offset
        let mut offset = self.next_offset.write().await;
        *offset += data.len() as u64;
        
        debug!("Wrote {} bytes to unidirectional stream {}", data.len(), self.id);
        Ok(())
    }
    
    /// Finish the stream
    pub async fn finish(&mut self) -> Result<()> {
        let send_tx = self.send_tx.as_ref()
            .ok_or(QuicError::Stream(StreamError::InvalidState))?;
        
        let mut state = self.state.write().await;
        *state = StreamState::Closed;
        drop(state);
        
        let stream_data = StreamData {
            offset: *self.next_offset.read().await,
            data: Bytes::new(),
            fin: true,
        };
        
        if let Err(_) = send_tx.send(stream_data) {
            return Err(QuicError::Stream(StreamError::Closed));
        }
        
        let mut finished = self.finished.write().await;
        *finished = true;
        
        debug!("Finished unidirectional stream {}", self.id);
        Ok(())
    }
    
    /// Read data from the stream (receive-only streams)
    pub async fn read_to_end(&mut self) -> Result<Vec<u8>> {
        let recv_rx = self.recv_rx.as_ref()
            .ok_or(QuicError::Stream(StreamError::InvalidState))?;
        
        let mut data = Vec::new();
        let mut recv_rx = recv_rx.lock().await;
        
        while let Some(stream_data) = recv_rx.recv().await {
            data.extend_from_slice(&stream_data.data);
            
            if stream_data.fin {
                let mut state = self.state.write().await;
                *state = StreamState::Closed;
                break;
            }
        }
        
        debug!("Read {} bytes from unidirectional stream {}", data.len(), self.id);
        Ok(data)
    }
    
    /// Check if stream is finished
    pub async fn is_finished(&self) -> bool {
        *self.finished.read().await
    }
    
    /// Get stream state
    pub async fn state(&self) -> StreamState {
        self.state.read().await.clone()
    }
}

impl BiStreamHandle {
    /// Get stream ID
    pub fn id(&self) -> StreamId {
        self.id
    }
    
    /// Deliver data to the stream
    pub async fn deliver_data(&self, data: StreamData) -> Result<()> {
        if let Err(_) = self.data_tx.send(data) {
            return Err(QuicError::Stream(StreamError::Closed));
        }
        Ok(())
    }
    
    /// Get stream state
    pub async fn state(&self) -> StreamState {
        self.state.read().await.clone()
    }
}

impl UniStreamHandle {
    /// Get stream ID
    pub fn id(&self) -> StreamId {
        self.id
    }
    
    /// Deliver data to the stream
    pub async fn deliver_data(&self, data: StreamData) -> Result<()> {
        if let Some(data_tx) = &self.data_tx {
            if let Err(_) = data_tx.send(data) {
                return Err(QuicError::Stream(StreamError::Closed));
            }
        }
        Ok(())
    }
    
    /// Get stream state
    pub async fn state(&self) -> StreamState {
        self.state.read().await.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_stream_id_properties() {
        let client_bi = StreamId::new(0);
        assert!(client_bi.is_client_initiated());
        assert!(client_bi.is_bidirectional());
        
        let server_bi = StreamId::new(1);
        assert!(server_bi.is_server_initiated());
        assert!(server_bi.is_bidirectional());
        
        let client_uni = StreamId::new(2);
        assert!(client_uni.is_client_initiated());
        assert!(client_uni.is_unidirectional());
        
        let server_uni = StreamId::new(3);
        assert!(server_uni.is_server_initiated());
        assert!(server_uni.is_unidirectional());
    }
    
    #[tokio::test]
    async fn test_bidirectional_stream_creation() {
        let stream_id = StreamId::new(0);
        let (stream, handle) = BiStream::new(stream_id);
        
        assert_eq!(stream.id(), stream_id);
        assert_eq!(handle.id(), stream_id);
        
        assert_eq!(stream.send_state().await, StreamState::Ready);
        assert_eq!(stream.recv_state().await, StreamState::Ready);
    }
    
    #[tokio::test]
    async fn test_unidirectional_stream_creation() {
        let stream_id = StreamId::new(2);
        let (stream, handle) = UniStream::new(stream_id);
        
        assert_eq!(stream.id(), stream_id);
        assert_eq!(handle.id(), stream_id);
        
        assert_eq!(stream.state().await, StreamState::Ready);
    }
    
    #[tokio::test]
    async fn test_stream_data() {
        let data = StreamData {
            offset: 0,
            data: Bytes::from("test data"),
            fin: false,
        };
        
        assert_eq!(data.offset, 0);
        assert_eq!(data.data, Bytes::from("test data"));
        assert!(!data.fin);
    }
}