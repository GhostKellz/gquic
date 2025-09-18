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

    #[error("Invalid state: {0}")]
    InvalidState(String),

    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    #[error("Flow control error: {0}")]
    FlowControl(String),

    #[error("Other error: {0}")]
    Other(String),

    #[error("Connection not found: {0}")]
    ConnectionNotFound(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

impl From<anyhow::Error> for QuicError {
    fn from(err: anyhow::Error) -> Self {
        QuicError::Crypto(err.to_string())
    }
}

impl From<crate::quic::error::QuicError> for QuicError {
    fn from(err: crate::quic::error::QuicError) -> Self {
        match err {
            crate::quic::error::QuicError::Connection(c) => QuicError::Protocol(format!("Connection: {:?}", c)),
            crate::quic::error::QuicError::Stream(s) => QuicError::Protocol(format!("Stream: {:?}", s)),
            crate::quic::error::QuicError::Crypto(c) => QuicError::Crypto(format!("Crypto: {:?}", c)),
            crate::quic::error::QuicError::Protocol(p) => QuicError::Protocol(format!("Protocol: {:?}", p)),
            crate::quic::error::QuicError::Io(i) => QuicError::Protocol(format!("IO: {}", i)),
            crate::quic::error::QuicError::FlowControl(f) => QuicError::FlowControl(f),
            crate::quic::error::QuicError::ConnectionClosed => QuicError::ConnectionClosed,
            _ => QuicError::Protocol(format!("QUIC error: {:?}", err)),
        }
    }
}

impl From<std::net::AddrParseError> for QuicError {
    fn from(err: std::net::AddrParseError) -> Self {
        QuicError::ConfigurationError(format!("Address parse error: {}", err))
    }
}

impl From<serde_json::Error> for QuicError {
    fn from(err: serde_json::Error) -> Self {
        QuicError::SerializationError(format!("JSON serialization error: {}", err))
    }
}

// Helper for creating protocol errors from strings
impl QuicError {
    pub fn protocol_error(msg: String) -> Self {
        QuicError::Protocol(msg)
    }
}
