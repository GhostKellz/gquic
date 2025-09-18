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

    #[error("Idle timeout")]
    IdleTimeout,
    
    #[error("Invalid packet: {0}")]
    InvalidPacket(String),
    
    #[error("Crypto error: {0}")]
    Crypto(String),
    
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),
    
    #[error("Key exchange failed: {0}")]
    KeyExchangeFailed(String),
    
    #[error("Blockchain validation error: {0}")]
    BlockchainError(String),
}
