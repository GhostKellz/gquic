use bytes::{Bytes, BytesMut, Buf, BufMut};
use std::fmt;

/// QUIC packet number
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PacketNumber(pub u64);

impl PacketNumber {
    pub fn new(n: u64) -> Self {
        Self(n)
    }
    
    pub fn value(&self) -> u64 {
        self.0
    }
    
    pub fn next(&self) -> Self {
        Self(self.0 + 1)
    }
}

impl fmt::Display for PacketNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// QUIC packet types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
    OneRtt,
}

impl PacketType {
    pub fn to_byte(&self) -> u8 {
        match self {
            PacketType::Initial => 0x00,
            PacketType::ZeroRtt => 0x01,
            PacketType::Handshake => 0x02,
            PacketType::Retry => 0x03,
            PacketType::OneRtt => 0x04,
        }
    }
    
    pub fn from_byte(b: u8) -> Option<Self> {
        match b & 0x30 {
            0x00 => Some(PacketType::Initial),
            0x10 => Some(PacketType::ZeroRtt),
            0x20 => Some(PacketType::Handshake),
            0x30 => Some(PacketType::Retry),
            _ => {
                if b & 0x80 == 0 {
                    Some(PacketType::OneRtt)
                } else {
                    None
                }
            }
        }
    }
}

/// QUIC packet header
#[derive(Debug, Clone)]
pub struct PacketHeader {
    pub packet_type: PacketType,
    pub connection_id: Bytes,
    pub packet_number: PacketNumber,
    pub version: Option<u32>,
}

impl PacketHeader {
    /// Encode header to bytes
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        
        // First byte with packet type
        let first_byte = self.packet_type.to_byte() | 0x80; // Set form bit
        buf.put_u8(first_byte);
        
        // Version (for long header packets)
        if let Some(version) = self.version {
            buf.put_u32(version);
        }
        
        // Connection ID length and value
        buf.put_u8(self.connection_id.len() as u8);
        buf.extend_from_slice(&self.connection_id);
        
        // Packet number (simplified - using 4 bytes)
        buf.put_u32(self.packet_number.value() as u32);
        
        buf.freeze()
    }
}

/// QUIC packet
#[derive(Debug, Clone)]
pub struct Packet {
    pub header: PacketHeader,
    pub payload: Bytes,
}

impl Packet {
    pub fn new(header: PacketHeader, payload: Bytes) -> Self {
        Self { header, payload }
    }
    
    /// Encode packet to bytes
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        
        // Encode header
        let first_byte = self.header.packet_type.to_byte() | 0x80; // Set form bit
        buf.put_u8(first_byte);
        
        // Version (for long header packets)
        if let Some(version) = self.header.version {
            buf.put_u32(version);
        }
        
        // Connection ID length and value
        buf.put_u8(self.header.connection_id.len() as u8);
        buf.extend_from_slice(&self.header.connection_id);
        
        // Packet number (simplified - using 4 bytes)
        buf.put_u32(self.header.packet_number.value() as u32);
        
        // Payload
        buf.extend_from_slice(&self.payload);
        
        buf.freeze()
    }
    
    /// Decode packet from bytes
    pub fn decode(mut data: Bytes) -> Result<Self, super::error::QuicError> {
        if data.is_empty() {
            return Err(super::error::QuicError::Protocol(super::error::ProtocolError::InvalidPacketFormat));
        }
        
        let first_byte = data.get_u8();
        let packet_type = PacketType::from_byte(first_byte)
            .ok_or_else(|| super::error::QuicError::Protocol(super::error::ProtocolError::InvalidPacketFormat))?;
        
        // Version (for long header packets)
        let version = if first_byte & 0x80 != 0 {
            if data.remaining() < 4 {
                return Err(super::error::QuicError::Protocol(super::error::ProtocolError::InvalidPacketFormat));
            }
            Some(data.get_u32())
        } else {
            None
        };
        
        // Connection ID
        if data.is_empty() {
            return Err(super::error::QuicError::Protocol(super::error::ProtocolError::InvalidConnectionIdLength));
        }
        let conn_id_len = data.get_u8() as usize;
        
        if data.remaining() < conn_id_len {
            return Err(super::error::QuicError::Protocol(super::error::ProtocolError::InvalidFrameFormat("Insufficient data for connection ID".to_string())));
        }
        let connection_id = data.copy_to_bytes(conn_id_len);
        
        // Packet number (simplified)
        if data.remaining() < 4 {
            return Err(super::error::QuicError::Protocol(super::error::ProtocolError::InvalidFrameFormat("Insufficient data for packet number".to_string())));
        }
        let packet_number = PacketNumber::new(data.get_u32() as u64);
        
        let header = PacketHeader {
            packet_type,
            connection_id,
            packet_number,
            version,
        };
        
        let payload = data;
        
        Ok(Packet::new(header, payload))
    }
}