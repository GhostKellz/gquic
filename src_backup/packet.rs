//! QUIC packet handling

use bytes::Bytes;
use crate::{ConnectionId, QuicError, QuicResult};

#[derive(Debug, Clone)]
pub struct Packet {
    connection_id: ConnectionId,
    data: Bytes,
}

impl Packet {
    pub fn new(connection_id: ConnectionId, data: Bytes) -> Self {
        Self { connection_id, data }
    }
    
    pub fn parse(data: &[u8]) -> QuicResult<Self> {
        if data.len() < 8 {
            return Err(QuicError::InvalidPacket("Too short".to_string()));
        }
        
        // Very basic parsing - just extract first 4 bytes as connection ID
        let conn_id = ConnectionId::new(data[0..4].to_vec());
        let packet_data = Bytes::copy_from_slice(data);
        
        Ok(Self::new(conn_id, packet_data))
    }
    
    pub fn connection_id(&self) -> &ConnectionId {
        &self.connection_id
    }
    
    pub fn data(&self) -> &Bytes {
        &self.data
    }
}
