//! QUIC frame types

use bytes::Bytes;

#[derive(Debug, Clone)]
pub enum Frame {
    Padding { length: usize },
    Ping,
    Data { data: Bytes },
    Close { error_code: u64, reason: String },
    // Crypto-specific frames for blockchain/crypto applications
    CryptoHandshake { key_exchange: Bytes },
    BlockchainData { chain_id: u64, block_hash: Bytes, data: Bytes },
    CryptoAuth { signature: Bytes, public_key: Bytes },
    SecureChannel { encrypted_payload: Bytes, nonce: Bytes },
}

impl Frame {
    pub fn parse(_data: &[u8]) -> Result<Self, crate::QuicError> {
        // Placeholder implementation
        Ok(Frame::Ping)
    }
    
    pub fn encode(&self) -> Vec<u8> {
        // Placeholder implementation
        vec![0]
    }
    
    /// Parse frame with crypto awareness
    pub fn parse_crypto(data: &[u8]) -> Result<Self, crate::QuicError> {
        if data.is_empty() {
            return Err(crate::QuicError::InvalidPacket("Empty frame data".to_string()));
        }
        
        match data[0] {
            0x00 => Ok(Frame::Padding { length: data.len() }),
            0x01 => Ok(Frame::Ping),
            0x02 => Ok(Frame::Data { data: Bytes::copy_from_slice(&data[1..]) }),
            0x03 => Ok(Frame::Close { 
                error_code: 0, 
                reason: "Connection closed".to_string() 
            }),
            // Crypto-specific frame types
            0x10 => Ok(Frame::CryptoHandshake { 
                key_exchange: Bytes::copy_from_slice(&data[1..]) 
            }),
            0x11 => Ok(Frame::BlockchainData { 
                chain_id: 1, 
                block_hash: Bytes::copy_from_slice(&data[1..9]),
                data: Bytes::copy_from_slice(&data[9..])
            }),
            0x12 => Ok(Frame::CryptoAuth { 
                signature: Bytes::copy_from_slice(&data[1..65]),
                public_key: Bytes::copy_from_slice(&data[65..])
            }),
            0x13 => Ok(Frame::SecureChannel { 
                encrypted_payload: Bytes::copy_from_slice(&data[1..data.len()-12]),
                nonce: Bytes::copy_from_slice(&data[data.len()-12..])
            }),
            _ => Ok(Frame::Ping), // Default fallback
        }
    }
    
    /// Encode frame for crypto applications
    pub fn encode_crypto(&self) -> Vec<u8> {
        match self {
            Frame::Padding { length } => vec![0x00; *length],
            Frame::Ping => vec![0x01],
            Frame::Data { data } => {
                let mut encoded = vec![0x02];
                encoded.extend_from_slice(data);
                encoded
            },
            Frame::Close { .. } => vec![0x03],
            Frame::CryptoHandshake { key_exchange } => {
                let mut encoded = vec![0x10];
                encoded.extend_from_slice(key_exchange);
                encoded
            },
            Frame::BlockchainData { chain_id, block_hash, data } => {
                let mut encoded = vec![0x11];
                encoded.extend_from_slice(&chain_id.to_be_bytes());
                encoded.extend_from_slice(block_hash);
                encoded.extend_from_slice(data);
                encoded
            },
            Frame::CryptoAuth { signature, public_key } => {
                let mut encoded = vec![0x12];
                encoded.extend_from_slice(signature);
                encoded.extend_from_slice(public_key);
                encoded
            },
            Frame::SecureChannel { encrypted_payload, nonce } => {
                let mut encoded = vec![0x13];
                encoded.extend_from_slice(encrypted_payload);
                encoded.extend_from_slice(nonce);
                encoded
            },
        }
    }
}
