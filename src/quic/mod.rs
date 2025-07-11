//! QUIC protocol implementation
//! 
//! This module contains the core QUIC protocol implementation including
//! connections, endpoints, streams, and packet handling.

pub mod connection;
pub mod endpoint;
pub mod error;
pub mod events;
pub mod frame;
pub mod scheduler;
pub mod stream;
pub mod packet;
pub mod udp_mux;

// Re-export commonly used items
pub use connection::{Connection, ConnectionId, ConnectionState, ConnectionStats, FlowController};
pub use endpoint::Endpoint;
pub use error::{QuicError, Result, ProtocolError, ConnectionError, StreamError};
pub use stream::{BiStream, UniStream, StreamId};
pub use packet::{Packet, PacketHeader, PacketNumber, PacketType};
pub use frame::Frame;