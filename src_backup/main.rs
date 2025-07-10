pub mod client;
pub mod server;
pub mod crypto;
pub mod pool;
pub mod metrics;
pub mod proto;
pub mod ffi;

pub use client::*;
pub use server::*;

#[cfg(feature = "gcrypt-integration")]
pub use crypto::gcrypt_backend;

pub mod prelude {
    pub use crate::client::{QuicClient, QuicClientBuilder, QuicClientConfig};
    pub use crate::server::{QuicServer, QuicServerBuilder, QuicServerConfig};
    pub use crate::pool::{ConnectionPool, PoolConfig};
    pub use anyhow::Result;
}
