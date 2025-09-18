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
        let conn_id = ConnectionId::from_bytes(&data[0..4]);
        let packet_data = Bytes::copy_from_slice(data);
        
        Ok(Self::new(conn_id, packet_data))
    }
    
    /// Parse with encryption awareness for crypto applications
    pub fn parse_encrypted(data: &[u8], key: &[u8]) -> QuicResult<Self> {
        if data.len() < 8 {
            return Err(QuicError::InvalidPacket("Packet too short".to_string()));
        }
        
        // Decrypt the packet (placeholder implementation)
        let decrypted: Vec<u8> = data.iter().zip(key.iter().cycle()).map(|(d, k)| d ^ k).collect();
        
        // Extract connection ID from decrypted data
        let conn_id = ConnectionId::from_bytes(&decrypted[0..4]);
        let packet_data = Bytes::copy_from_slice(&decrypted);
        
        Ok(Self::new(conn_id, packet_data))
    }
    
    pub fn connection_id(&self) -> &ConnectionId {
        &self.connection_id
    }
    
    pub fn data(&self) -> &Bytes {
        &self.data
    }
    
    /// Encode packet with encryption for crypto applications
    pub fn encode_encrypted(&self, key: &[u8]) -> Vec<u8> {
        let plaintext = self.data.as_ref();
        // Encrypt the packet (placeholder implementation)
        plaintext.iter().zip(key.iter().cycle()).map(|(d, k)| d ^ k).collect()
    }
    
    /// Validate packet integrity (placeholder for real crypto validation)
    pub fn validate_integrity(&self, expected_hash: &[u8]) -> bool {
        // In a real implementation, this would verify cryptographic integrity
        let computed_hash = self.compute_hash();
        computed_hash == expected_hash
    }
    
    /// Compute packet hash (placeholder)
    pub fn compute_hash(&self) -> Vec<u8> {
        // Simple hash - replace with real cryptographic hash
        let mut hash = vec![0u8; 32];
        for (i, byte) in self.data.iter().enumerate() {
            hash[i % 32] ^= byte;
        }
        hash
    }
}
