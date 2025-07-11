//! HTTP/3 implementation over QUIC
//! 
//! This module provides a complete HTTP/3 implementation built on top of the GQUIC
//! transport layer. It includes support for:
//! 
//! - HTTP/3 request/response semantics
//! - QPACK header compression
//! - Server push
//! - HTTP/3 frames and stream multiplexing
//! - Integration with QUIC flow control

pub mod connection;
pub mod stream;
pub mod frame;
pub mod headers;
pub mod request;
pub mod response;
pub mod client;
pub mod server;
pub mod error;
pub mod qpack;

// Re-exports for convenience
pub use connection::Http3Connection;
pub use client::Http3Client;
pub use server::Http3Server;
pub use request::Http3Request;
pub use response::Http3Response;
pub use error::Http3Error;
pub use frame::{Http3Frame, Http3FrameType};
pub use headers::Http3Headers;
pub use stream::Http3Stream;

/// HTTP/3 stream types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Http3StreamType {
    /// Bidirectional stream for requests/responses
    Request,
    /// Unidirectional control stream
    Control,
    /// Unidirectional push stream
    Push,
    /// QPACK encoder stream
    QpackEncoder,
    /// QPACK decoder stream
    QpackDecoder,
}

/// HTTP/3 stream state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Http3StreamState {
    /// Stream is open and ready for data
    Open,
    /// Stream is half-closed (local)
    HalfClosedLocal,
    /// Stream is half-closed (remote)
    HalfClosedRemote,
    /// Stream is fully closed
    Closed,
    /// Stream reset by peer
    Reset,
}

/// HTTP/3 settings and configuration
#[derive(Debug, Clone)]
pub struct Http3Settings {
    pub max_field_section_size: u64,
    pub qpack_max_table_capacity: u64,
    pub qpack_blocked_streams: u64,
}

impl Default for Http3Settings {
    fn default() -> Self {
        Self {
            max_field_section_size: 16384,
            qpack_max_table_capacity: 4096,
            qpack_blocked_streams: 100,
        }
    }
}
