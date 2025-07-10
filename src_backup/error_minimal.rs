//! QUIC error types

use std::io;

#[derive(Debug, thiserror::Error)]
pub enum QuicError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    
    #[error("Protocol error: {0}")]
    Protocol(String),
    
    #[error("Connection closed")]
    ConnectionClosed,
    
    #[error("Invalid packet: {0}")]
    InvalidPacket(String),
}
