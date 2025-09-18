use thiserror::Error;

/// QUIC protocol specific errors
#[derive(Debug, Clone, Error)]
pub enum ProtocolError {
    #[error("Invalid frame format: {0}")]
    InvalidFrameFormat(String),
    
    #[error("Invalid packet: {0}")]
    InvalidPacket(String),
    
    #[error("Invalid packet format: {0}")]
    InvalidPacketFormat(String),
    
    #[error("Invalid connection ID: {0}")]
    InvalidConnectionId(String),
    
    #[error("Invalid connection ID length: {0}")]
    InvalidConnectionIdLength(String),
    
    #[error("Invalid stream ID: {0}")]
    InvalidStreamId(String),
    
    #[error("Flow control violation: {0}")]
    FlowControlViolation(String),
    
    #[error("Transport parameter error: {0}")]
    TransportParameter(String),
    
    #[error("Version negotiation failed: {0}")]
    VersionNegotiation(String),
    
    #[error("Unsupported version: {0}")]
    UnsupportedVersion(String),
    
    #[error("Packet number out of range: {0}")]
    PacketNumberOutOfRange(String),
    
    #[error("Duplicate packet number: {0}")]
    DuplicatePacketNumber(String),
    
    #[error("Frame not allowed: {0}")]
    FrameNotAllowed(String),

    #[error("Invalid state: {0}")]
    InvalidState(String),
}

#[derive(Error, Debug, Clone)]
pub enum QuicError {
    #[error("Connection error: {0}")]
    Connection(#[from] ConnectionError),
    
    #[error("Stream error: {0}")]
    Stream(#[from] StreamError),
    
    #[error("Cryptographic error: {0}")]
    Crypto(#[from] CryptoError),
    
    #[error("Protocol violation: {0}")]
    Protocol(#[from] ProtocolError),

    #[error("HTTP/3 error: {0}")]
    Http3(String),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("Invalid state: {0}")]
    InvalidState(String),

    #[error("Configuration error: {0}")]
    ConfigurationError(String),
    
    #[error("IO error: {0}")]
    Io(String), // String instead of std::io::Error for Clone
    
    #[error("Transport parameter error: {0}")]
    TransportParameter(String),
    
    #[error("Configuration error: {0}")]
    Config(String),
    
    #[error("Rate limit exceeded: {0}")]
    RateLimit(String),
    
    #[error("Security violation: {0}")]
    Security(#[from] SecurityError),
    
    #[error("Timeout: {0}")]
    Timeout(TimeoutError),
    
    #[error("Packet processing error: {0}")]
    Packet(#[from] PacketError),

    #[error("Flow control error: {0}")]
    FlowControl(String),

    #[error("Connection closed")]
    ConnectionClosed,
}

impl From<std::io::Error> for QuicError {
    fn from(err: std::io::Error) -> Self {
        QuicError::Io(err.to_string())
    }
}

impl From<anyhow::Error> for QuicError {
    fn from(err: anyhow::Error) -> Self {
        QuicError::Crypto(CryptoError::Generic(err.to_string()))
    }
}

#[derive(Error, Debug, Clone)]
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
    
    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),
    
    #[error("Connection migration failed")]
    MigrationFailed,
    
    #[error("Transport parameter mismatch")]
    TransportParameterMismatch,

    #[error("Invalid state: {0}")]
    InvalidState(String),

    #[error("Internal error")]
    InternalError,
}

#[derive(Error, Debug, Clone)]
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
    
    #[error("Stream data blocked")]
    DataBlocked,
    
    #[error("Stream not found")]
    NotFound,
    
    #[error("Stream already exists")]
    AlreadyExists,
}

#[derive(Error, Debug, Clone)]
pub enum CryptoError {
    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),
    
    #[error("Encryption failed: {0}")]
    Encryption(String),
    
    #[error("Decryption failed: {0}")]
    Decryption(String),
    
    #[error("Header protection failed: {0}")]
    HeaderProtection(String),
    
    #[error("Signature verification failed")]
    SignatureVerification,
    
    #[error("Invalid key length")]
    InvalidKeyLength,
    
    #[error("Nonce reuse detected")]
    NonceReuse,
    
    #[error("Generic crypto error: {0}")]
    Generic(String),
}

#[derive(Error, Debug, Clone)]
pub enum SecurityError {
    #[error("DDoS protection triggered: {0}")]
    DdosProtection(String),
    
    #[error("Rate limit exceeded for {resource}: {limit} per {window:?}")]
    RateLimitExceeded { resource: String, limit: u64, window: std::time::Duration },
    
    #[error("Invalid certificate: {0}")]
    InvalidCertificate(String),
    
    #[error("Untrusted peer")]
    UntrustedPeer,
    
    #[error("Amplification attack detected")]
    AmplificationAttack,
    
    #[error("Invalid token")]
    InvalidToken,
    
    #[error("Retry limit exceeded")]
    RetryLimitExceeded,
}

#[derive(Error, Debug, Clone)]
pub enum TimeoutError {
    #[error("Handshake timeout")]
    Handshake,
    
    #[error("Idle timeout")]
    Idle,
    
    #[error("Keep alive timeout")]
    KeepAlive,
    
    #[error("Packet acknowledgment timeout")]
    PacketAck,
    
    #[error("Stream data timeout")]
    StreamData,
}

#[derive(Error, Debug, Clone)]
pub enum PacketError {
    #[error("Packet too small: {size} bytes")]
    TooSmall { size: usize },
    
    #[error("Packet too large: {size} bytes, max: {max}")]
    TooLarge { size: usize, max: usize },
    
    #[error("Invalid header")]
    InvalidHeader,
    
    #[error("Checksum mismatch")]
    ChecksumMismatch,
    
    #[error("Unsupported packet type: {0}")]
    UnsupportedType(u8),
    
    #[error("Incomplete packet data")]
    IncompleteData,
}

/// Error recovery action suggestions
#[derive(Debug, Clone)]
pub enum RecoveryAction {
    /// Retry the operation after a delay
    Retry { delay: std::time::Duration, max_attempts: u32 },
    /// Close the connection gracefully
    CloseConnection { error_code: u64, reason: String },
    /// Reset the stream
    ResetStream { stream_id: u64, error_code: u64 },
    /// Ignore the error and continue
    Ignore,
    /// Initiate connection migration
    MigrateConnection,
    /// Request key update
    UpdateKeys,
    /// Reduce send rate
    ReduceSendRate { factor: f64 },
}

impl QuicError {
    /// Get suggested recovery action for this error
    pub fn recovery_action(&self) -> RecoveryAction {
        match self {
            QuicError::Io(_) => RecoveryAction::Retry { 
                delay: std::time::Duration::from_millis(100), 
                max_attempts: 3 
            },
            QuicError::Connection(ConnectionError::Timeout) => RecoveryAction::CloseConnection {
                error_code: 0x2,
                reason: "Connection timeout".to_string(),
            },
            QuicError::Stream(StreamError::FlowControl) => RecoveryAction::ReduceSendRate { factor: 0.5 },
            QuicError::Crypto(CryptoError::NonceReuse) => RecoveryAction::UpdateKeys,
            QuicError::Security(SecurityError::DdosProtection(_)) => RecoveryAction::CloseConnection {
                error_code: 0x1,
                reason: "Security violation".to_string(),
            },
            QuicError::Timeout(TimeoutError::Handshake) => RecoveryAction::CloseConnection {
                error_code: 0x2,
                reason: "Handshake timeout".to_string(),
            },
            _ => RecoveryAction::Ignore,
        }
    }
    
    /// Check if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        match self {
            QuicError::Io(_) => true,
            QuicError::Stream(StreamError::DataBlocked) => true,
            QuicError::Timeout(TimeoutError::PacketAck) => true,
            QuicError::Connection(ConnectionError::MigrationFailed) => true,
            _ => false,
        }
    }
    
    /// Get error severity level
    pub fn severity(&self) -> ErrorSeverity {
        match self {
            QuicError::Security(_) => ErrorSeverity::Critical,
            QuicError::Connection(ConnectionError::Closed) => ErrorSeverity::Critical,
            QuicError::Crypto(_) => ErrorSeverity::High,
            QuicError::Protocol(_) => ErrorSeverity::High,
            QuicError::Stream(_) => ErrorSeverity::Medium,
            QuicError::Timeout(_) => ErrorSeverity::Medium,
            QuicError::Io(_) => ErrorSeverity::Low,
            _ => ErrorSeverity::Low,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ErrorSeverity {
    Low,
    Medium,
    High,
    Critical,
}

pub type Result<T> = std::result::Result<T, QuicError>;