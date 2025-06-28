// Core QUIC implementation - replaces Quinn
pub mod quic;

// High-level client/server abstractions 
pub mod client;
pub mod server;

// Cryptography backend integration
pub mod crypto;

// Connection pooling and management
pub mod pool;

// Metrics and monitoring
pub mod metrics;

// Protocol buffer definitions
pub mod proto;

// FFI for Zig integration
pub mod ffi;

// Re-export main types
pub use quic::{Connection, Endpoint, EndpointConfig, EndpointEvent, BiStream, UniStream, StreamId};

#[cfg(feature = "gcrypt-integration")]
pub use crypto::gcrypt_backend;

pub mod prelude {
    pub use crate::quic::{Connection, Endpoint, EndpointConfig, EndpointEvent, BiStream, UniStream, StreamId};
    pub use crate::client::{QuicClient, QuicClientBuilder, QuicClientConfig};
    pub use crate::server::{QuicServer, QuicServerBuilder, QuicServerConfig};
    pub use crate::pool::{ConnectionPool, PoolConfig};
    pub use anyhow::Result;
}