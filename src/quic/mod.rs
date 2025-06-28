// Core QUIC protocol implementation for GhostChain
// Replaces Quinn with minimal, high-performance implementation

pub mod packet;
pub mod frame;
pub mod connection;
pub mod stream;
pub mod endpoint;
pub mod error;
pub mod udp_mux;
pub mod congestion;
pub mod loss_recovery;
pub mod ack_manager;
pub mod migration;
pub mod bandwidth_estimator;
pub mod shutdown;
pub mod datagram;
pub mod scheduler;
pub mod connection_id_manager;
pub mod events;
pub mod alpn;

pub use connection::{Connection, ConnectionId, ConnectionState};
pub use endpoint::{Endpoint, EndpointConfig, EndpointEvent};
pub use stream::{BiStream, UniStream, StreamId};
pub use error::{QuicError, ConnectionError, StreamError};

// Re-export common types
pub use packet::{Packet, PacketType, PacketNumber};
pub use frame::{Frame, FrameType};