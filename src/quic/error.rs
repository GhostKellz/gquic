use thiserror::Error;

#[derive(Error, Debug)]
pub enum QuicError {
    #[error("Connection error: {0}")]
    Connection(#[from] ConnectionError),
    
    #[error("Stream error: {0}")]
    Stream(#[from] StreamError),
    
    #[error("Cryptographic error: {0}")]
    Crypto(String),
    
    #[error("Protocol violation: {0}")]
    Protocol(String),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Transport parameter error: {0}")]
    TransportParameter(String),
}

#[derive(Error, Debug)]
pub enum ConnectionError {
    #[error("Connection closed")]
    Closed,
    
    #[error("Connection timeout")]
    Timeout,
    
    #[error("Connection reset")]
    Reset,
    
    #[error("Idle timeout")]
    IdleTimeout,
    
    #[error("Version negotiation failed")]
    VersionNegotiation,
    
    #[error("TLS error: {0}")]
    Tls(String),
}

#[derive(Error, Debug)]
pub enum StreamError {
    #[error("Stream closed")]
    Closed,
    
    #[error("Stream reset")]
    Reset,
    
    #[error("Flow control error")]
    FlowControl,
    
    #[error("Stream limit exceeded")]
    StreamLimit,
    
    #[error("Invalid stream state")]
    InvalidState,
}

pub type Result<T> = std::result::Result<T, QuicError>;