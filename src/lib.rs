//! GQUIC v0.3.0 - High-Performance QUIC Library for Crypto Applications
//! 
//! A fully-featured QUIC transport implementation designed specifically for
//! cryptocurrency applications, trading systems, and other high-performance
//! networking applications requiring low latency and high throughput.

// Core QUIC implementation - replaces Quinn
pub mod quic;

// High-level client/server abstractions 
pub mod client;
pub mod server;

// Cryptography backend integration
pub mod crypto;

// Configuration and validation
pub mod config;

// Security features (rate limiting, DDoS protection)
pub mod security;

// Connection pooling and management
pub mod pool;

// Metrics and monitoring
pub mod metrics;

// Observability and monitoring tools
pub mod observability;

// Protocol buffer definitions
pub mod proto;

// FFI for Zig integration
#[cfg(feature = "ffi")]
pub mod ffi;

// Re-export main types for easier usage
pub use quic::{
    Connection, ConnectionId, ConnectionState,
    Endpoint, EndpointConfig, EndpointEvent,
    BiStream, UniStream, StreamId,
    QuicError, ConnectionError, StreamError,
};

pub use crypto::{CryptoBackend, QuicCrypto};

#[cfg(feature = "gcrypt-integration")]
pub use crypto::gcrypt_backend;

/// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Prelude module for common imports
pub mod prelude {
    pub use crate::quic::{Connection, Endpoint, EndpointConfig, EndpointEvent, BiStream, UniStream, StreamId};
    pub use crate::client::{QuicClient, QuicClientBuilder, QuicClientConfig};
    pub use crate::server::{QuicServer, QuicServerBuilder, QuicServerConfig};
    pub use crate::crypto::{CryptoBackend, QuicCrypto};
    pub use anyhow::Result;
}