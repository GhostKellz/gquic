//! QUIC frame types

use bytes::Bytes;

#[derive(Debug, Clone)]
pub enum Frame {
    Padding { length: usize },
    Ping,
    Data { data: Bytes },
    Close { error_code: u64, reason: String },
}

impl Frame {
    pub fn parse(_data: &[u8]) -> Result<Self, crate::QuicError> {
        // Placeholder implementation
        Ok(Frame::Ping)
    }
    
    pub fn encode(&self) -> Vec<u8> {
        // Placeholder implementation
        vec![0]
    }
}
