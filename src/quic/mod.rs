// Core QUIC protocol implementation for GhostChain
// Replaces Quinn with minimal, high-performance implementation

pub mod packet;
pub mod frame;
pub mod connection;
pub mod stream;
pub mod endpoint;
pub mod error;

pub use connection::{Connection, ConnectionId, ConnectionState};
pub use endpoint::{Endpoint, EndpointConfig, EndpointEvent};
pub use stream::{BiStream, UniStream, StreamId};
pub use error::{QuicError, ConnectionError, StreamError};

// Re-export common types
pub use packet::{Packet, PacketType, PacketNumber};
pub use frame::{Frame, FrameType};