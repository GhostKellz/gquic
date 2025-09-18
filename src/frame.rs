//! QUIC frame types

use bytes::Bytes;

#[derive(Debug, Clone)]
pub enum Frame {
    // Standard QUIC frames
    Padding { length: usize },
    Ping,
    Ack { largest_acknowledged: u64, ack_delay: u64 },
    ResetStream { stream_id: u64, application_error_code: u64, final_size: u64 },
    StopSending { stream_id: u64, application_error_code: u64 },
    Crypto { offset: u64, data: Bytes },
    NewToken { token: Bytes },
    Stream {
        stream_id: u64,
        offset: u64,
        data: Bytes,
        fin: bool
    },
    MaxData { maximum_data: u64 },
    MaxStreamData { stream_id: u64, maximum_stream_data: u64 },
    MaxStreams { maximum_streams: u64 },
    DataBlocked { maximum_data: u64 },
    StreamDataBlocked { stream_id: u64, maximum_stream_data: u64 },
    StreamsBlocked { maximum_streams: u64 },
    NewConnectionId {
        sequence_number: u64,
        retire_prior_to: u64,
        connection_id: Bytes,
        stateless_reset_token: [u8; 16]
    },
    RetireConnectionId { sequence_number: u64 },
    PathChallenge { data: [u8; 8] },
    PathResponse { data: [u8; 8] },
    ConnectionClose {
        error_code: u64,
        frame_type: Option<u64>,
        reason_phrase: String
    },
    ApplicationClose {
        error_code: u64,
        reason_phrase: String
    },
    HandshakeDone,

    // Extension: Immediate close frame for faster shutdown
    ImmediateClose {
        error_code: u64,
        reason: String,
        final_offset: u64,
    },

    // Legacy data frame for compatibility
    Data { data: Bytes },

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
            0x1c => {
                // CONNECTION_CLOSE frame (0x1c)
                if data.len() < 9 {
                    return Err(crate::QuicError::InvalidPacket("CONNECTION_CLOSE frame too short".to_string()));
                }
                let error_code = u64::from_be_bytes([0, 0, 0, 0, 0, 0, 0, 0]);
                let reason_phrase = String::from_utf8_lossy(&data[9..]).to_string();
                Ok(Frame::ConnectionClose {
                    error_code,
                    frame_type: None,
                    reason_phrase,
                })
            },
            0x1d => {
                // APPLICATION_CLOSE frame (0x1d)
                if data.len() < 9 {
                    return Err(crate::QuicError::InvalidPacket("APPLICATION_CLOSE frame too short".to_string()));
                }
                let error_code = u64::from_be_bytes([0, 0, 0, 0, 0, 0, 0, 0]);
                let reason_phrase = String::from_utf8_lossy(&data[9..]).to_string();
                Ok(Frame::ApplicationClose {
                    error_code,
                    reason_phrase,
                })
            },
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
            Frame::ConnectionClose { error_code, reason_phrase, .. } => {
                let mut encoded = vec![0x1c];
                encoded.extend_from_slice(&error_code.to_be_bytes());
                encoded.extend_from_slice(reason_phrase.as_bytes());
                encoded
            },
            Frame::ApplicationClose { error_code, reason_phrase } => {
                let mut encoded = vec![0x1d];
                encoded.extend_from_slice(&error_code.to_be_bytes());
                encoded.extend_from_slice(reason_phrase.as_bytes());
                encoded
            },
            Frame::ImmediateClose { error_code, reason, final_offset } => {
                let mut encoded = vec![0xfe]; // Custom immediate close frame type
                encoded.extend_from_slice(&error_code.to_be_bytes());
                encoded.extend_from_slice(&final_offset.to_be_bytes());
                encoded.extend_from_slice(reason.as_bytes());
                encoded
            },
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
            Frame::Ack { largest_acknowledged, ack_delay } => {
                let mut encoded = vec![0x02];
                encoded.extend_from_slice(&largest_acknowledged.to_be_bytes());
                encoded.extend_from_slice(&ack_delay.to_be_bytes());
                encoded
            },
            Frame::Crypto { offset, data } => {
                let mut encoded = vec![0x06];
                encoded.extend_from_slice(&offset.to_be_bytes());
                encoded.extend_from_slice(&(data.len() as u64).to_be_bytes());
                encoded.extend_from_slice(data);
                encoded
            },
            Frame::Stream { stream_id, offset, data, fin } => {
                let frame_type = if *fin { 0x0f } else { 0x0e };
                let mut encoded = vec![frame_type];
                encoded.extend_from_slice(&stream_id.to_be_bytes());
                encoded.extend_from_slice(&offset.to_be_bytes());
                encoded.extend_from_slice(&(data.len() as u64).to_be_bytes());
                encoded.extend_from_slice(data);
                encoded
            },
            Frame::NewConnectionId { sequence_number, retire_prior_to, connection_id, stateless_reset_token } => {
                let mut encoded = vec![0x18];
                encoded.extend_from_slice(&sequence_number.to_be_bytes());
                encoded.extend_from_slice(&retire_prior_to.to_be_bytes());
                encoded.push(connection_id.len() as u8);
                encoded.extend_from_slice(connection_id);
                encoded.extend_from_slice(stateless_reset_token);
                encoded
            },
            Frame::PathChallenge { data } => {
                let mut encoded = vec![0x1a];
                encoded.extend_from_slice(data);
                encoded
            },
            Frame::PathResponse { data } => {
                let mut encoded = vec![0x1b];
                encoded.extend_from_slice(data);
                encoded
            },
            Frame::HandshakeDone => vec![0x1e],
            _ => vec![0x01], // Default to PING for unhandled frames
        }
    }
}
