// HTTP/3 error types

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Http3Error {
    #[error("Protocol error: {0}")]
    ProtocolError(String),
    
    #[error("Stream error on stream {stream_id}: {error}")]
    StreamError { stream_id: u64, error: String },
    
    #[error("Connection error: {0}")]
    ConnectionError(String),
    
    #[error("QPACK error: {0}")]
    QpackError(String),
    
    #[error("Settings error: {0}")]
    SettingsError(String),
    
    #[error("Frame error: {0}")]
    FrameError(String),
    
    #[error("Transport error: {0}")]
    TransportError(#[from] crate::quic::QuicError),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Invalid header: {0}")]
    InvalidHeader(String),
    
    #[error("Request too large")]
    RequestTooLarge,
    
    #[error("Response too large")]
    ResponseTooLarge,
    
    #[error("Connection closed")]
    ConnectionClosed,
    
    #[error("Stream not found: {0}")]
    StreamNotFound(u64),
    
    #[error("Invalid stream state")]
    InvalidStreamState,
    
    #[error("Server push not supported")]
    PushNotSupported,
    
    #[error("ALPN negotiation failed")]
    AlpnNegotiationFailed,
    
    #[error("HTTP/3 not negotiated")]
    Http3NotNegotiated,
}

// HTTP/3 error codes as defined in RFC 9114
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Http3ErrorCode {
    NoError = 0x0100,
    GeneralProtocolError = 0x0101,
    InternalError = 0x0102,
    StreamCreationError = 0x0103,
    ClosedCriticalStream = 0x0104,
    FrameUnexpected = 0x0105,
    FrameError = 0x0106,
    ExcessiveLoad = 0x0107,
    IdError = 0x0108,
    SettingsError = 0x0109,
    MissingSettings = 0x010a,
    RequestRejected = 0x010b,
    RequestCancelled = 0x010c,
    RequestIncomplete = 0x010d,
    MessageError = 0x010e,
    ConnectError = 0x010f,
    VersionFallback = 0x0110,
    QpackDecompressionFailed = 0x0200,
    QpackEncoderStreamError = 0x0201,
    QpackDecoderStreamError = 0x0202,
}

impl From<Http3ErrorCode> for u64 {
    fn from(code: Http3ErrorCode) -> u64 {
        code as u64
    }
}

impl From<u64> for Http3ErrorCode {
    fn from(code: u64) -> Self {
        match code {
            0x0100 => Http3ErrorCode::NoError,
            0x0101 => Http3ErrorCode::GeneralProtocolError,
            0x0102 => Http3ErrorCode::InternalError,
            0x0103 => Http3ErrorCode::StreamCreationError,
            0x0104 => Http3ErrorCode::ClosedCriticalStream,
            0x0105 => Http3ErrorCode::FrameUnexpected,
            0x0106 => Http3ErrorCode::FrameError,
            0x0107 => Http3ErrorCode::ExcessiveLoad,
            0x0108 => Http3ErrorCode::IdError,
            0x0109 => Http3ErrorCode::SettingsError,
            0x010a => Http3ErrorCode::MissingSettings,
            0x010b => Http3ErrorCode::RequestRejected,
            0x010c => Http3ErrorCode::RequestCancelled,
            0x010d => Http3ErrorCode::RequestIncomplete,
            0x010e => Http3ErrorCode::MessageError,
            0x010f => Http3ErrorCode::ConnectError,
            0x0110 => Http3ErrorCode::VersionFallback,
            0x0200 => Http3ErrorCode::QpackDecompressionFailed,
            0x0201 => Http3ErrorCode::QpackEncoderStreamError,
            0x0202 => Http3ErrorCode::QpackDecoderStreamError,
            _ => Http3ErrorCode::GeneralProtocolError,
        }
    }
}

impl Http3Error {
    pub fn error_code(&self) -> Http3ErrorCode {
        match self {
            Http3Error::ProtocolError(_) => Http3ErrorCode::GeneralProtocolError,
            Http3Error::StreamError { .. } => Http3ErrorCode::StreamCreationError,
            Http3Error::ConnectionError(_) => Http3ErrorCode::InternalError,
            Http3Error::QpackError(_) => Http3ErrorCode::QpackDecompressionFailed,
            Http3Error::SettingsError(_) => Http3ErrorCode::SettingsError,
            Http3Error::FrameError(_) => Http3ErrorCode::FrameError,
            Http3Error::TransportError(_) => Http3ErrorCode::InternalError,
            Http3Error::IoError(_) => Http3ErrorCode::InternalError,
            Http3Error::InvalidHeader(_) => Http3ErrorCode::MessageError,
            Http3Error::RequestTooLarge => Http3ErrorCode::ExcessiveLoad,
            Http3Error::ResponseTooLarge => Http3ErrorCode::ExcessiveLoad,
            Http3Error::ConnectionClosed => Http3ErrorCode::NoError,
            Http3Error::StreamNotFound(_) => Http3ErrorCode::IdError,
            Http3Error::InvalidStreamState => Http3ErrorCode::StreamCreationError,
            Http3Error::PushNotSupported => Http3ErrorCode::RequestRejected,
            Http3Error::AlpnNegotiationFailed => Http3ErrorCode::ConnectError,
            Http3Error::Http3NotNegotiated => Http3ErrorCode::VersionFallback,
        }
    }
}
