//! QUIC packet implementation
//!
//! This module provides packet structure and handling for QUIC protocol
//! including packet types, headers, and serialization/deserialization.

use crate::quic::error::{QuicError, Result, PacketError};
use bytes::{Bytes, BytesMut, Buf, BufMut};
use std::fmt;

/// QUIC packet types as defined in RFC 9000
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    /// Initial packet for connection establishment
    Initial,
    /// 0-RTT packet for early data
    ZeroRtt,
    /// Handshake packet for TLS handshake
    Handshake,
    /// Retry packet for address validation
    Retry,
    /// 1-RTT packet for application data
    OneRtt,
    /// Version negotiation packet
    VersionNegotiation,
}

impl PacketType {
    /// Get packet type from byte value
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x00 => Some(PacketType::Initial),
            0x01 => Some(PacketType::ZeroRtt),
            0x02 => Some(PacketType::Handshake),
            0x03 => Some(PacketType::Retry),
            0x04 => Some(PacketType::OneRtt),
            0xFF => Some(PacketType::VersionNegotiation),
            _ => None,
        }
    }
    
    /// Convert packet type to byte value
    pub fn to_byte(self) -> u8 {
        match self {
            PacketType::Initial => 0x00,
            PacketType::ZeroRtt => 0x01,
            PacketType::Handshake => 0x02,
            PacketType::Retry => 0x03,
            PacketType::OneRtt => 0x04,
            PacketType::VersionNegotiation => 0xFF,
        }
    }
    
    /// Check if this is a long header packet
    pub fn is_long_header(self) -> bool {
        match self {
            PacketType::Initial | PacketType::ZeroRtt | PacketType::Handshake | 
            PacketType::Retry | PacketType::VersionNegotiation => true,
            PacketType::OneRtt => false,
        }
    }
}

/// QUIC packet number
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PacketNumber(u64);

impl PacketNumber {
    /// Create a new packet number
    pub fn new(value: u64) -> Self {
        Self(value)
    }
    
    /// Get the packet number value
    pub fn value(self) -> u64 {
        self.0
    }
    
    /// Get the next packet number
    pub fn next(self) -> Self {
        Self(self.0 + 1)
    }
    
    /// Encode packet number with variable length
    pub fn encode(&self, largest_acked: Option<PacketNumber>) -> Vec<u8> {
        let value = self.0;
        
        // Determine the number of bytes needed
        let bytes_needed = if let Some(largest) = largest_acked {
            let diff = value.saturating_sub(largest.0);
            if diff < 0x80 {
                1
            } else if diff < 0x8000 {
                2
            } else if diff < 0x800000 {
                3
            } else {
                4
            }
        } else {
            // No largest acked, use minimum bytes
            if value < 0x80 {
                1
            } else if value < 0x8000 {
                2
            } else if value < 0x800000 {
                3
            } else {
                4
            }
        };
        
        match bytes_needed {
            1 => vec![value as u8],
            2 => {
                let mut buf = vec![0u8; 2];
                buf[0] = ((value >> 8) | 0x80) as u8;
                buf[1] = value as u8;
                buf
            }
            3 => {
                let mut buf = vec![0u8; 3];
                buf[0] = ((value >> 16) | 0xC0) as u8;
                buf[1] = (value >> 8) as u8;
                buf[2] = value as u8;
                buf
            }
            4 => {
                let mut buf = vec![0u8; 4];
                buf[0] = ((value >> 24) | 0xE0) as u8;
                buf[1] = (value >> 16) as u8;
                buf[2] = (value >> 8) as u8;
                buf[3] = value as u8;
                buf
            }
            _ => unreachable!(),
        }
    }
    
    /// Decode packet number from bytes
    pub fn decode(data: &[u8]) -> Result<(Self, usize)> {
        if data.is_empty() {
            return Err(QuicError::Packet(PacketError::IncompleteData));
        }
        
        let first_byte = data[0];
        let length = ((first_byte & 0xC0) >> 6) + 1;
        
        if data.len() < length as usize {
            return Err(QuicError::Packet(PacketError::IncompleteData));
        }
        
        let value = match length {
            1 => first_byte as u64,
            2 => {
                let mut value = ((first_byte & 0x3F) as u64) << 8;
                value |= data[1] as u64;
                value
            }
            3 => {
                let mut value = ((first_byte & 0x3F) as u64) << 16;
                value |= (data[1] as u64) << 8;
                value |= data[2] as u64;
                value
            }
            4 => {
                let mut value = ((first_byte & 0x3F) as u64) << 24;
                value |= (data[1] as u64) << 16;
                value |= (data[2] as u64) << 8;
                value |= data[3] as u64;
                value
            }
            _ => return Err(QuicError::Packet(PacketError::InvalidHeader)),
        };
        
        Ok((Self(value), length as usize))
    }
}

impl fmt::Display for PacketNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// QUIC packet header
#[derive(Debug, Clone)]
pub struct PacketHeader {
    /// Packet type
    pub packet_type: PacketType,
    /// Connection ID
    pub connection_id: Bytes,
    /// Packet number
    pub packet_number: PacketNumber,
    /// QUIC version (for long header packets)
    pub version: Option<u32>,
    /// Source connection ID (for long header packets)
    pub source_connection_id: Option<Bytes>,
    /// Destination connection ID (for long header packets)
    pub destination_connection_id: Option<Bytes>,
    /// Token (for Initial and Retry packets)
    pub token: Option<Bytes>,
    /// Length (for long header packets)
    pub length: Option<u64>,
}

impl PacketHeader {
    /// Create a new packet header
    pub fn new(
        packet_type: PacketType,
        connection_id: Bytes,
        packet_number: PacketNumber,
    ) -> Self {
        Self {
            packet_type,
            connection_id,
            packet_number,
            version: None,
            source_connection_id: None,
            destination_connection_id: None,
            token: None,
            length: None,
        }
    }
    
    /// Create a long header packet
    pub fn long_header(
        packet_type: PacketType,
        version: u32,
        destination_connection_id: Bytes,
        source_connection_id: Bytes,
        packet_number: PacketNumber,
    ) -> Self {
        Self {
            packet_type,
            connection_id: destination_connection_id.clone(),
            packet_number,
            version: Some(version),
            source_connection_id: Some(source_connection_id),
            destination_connection_id: Some(destination_connection_id),
            token: None,
            length: None,
        }
    }
    
    /// Encode packet header to bytes
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        
        if self.packet_type.is_long_header() {
            // Long header format
            let first_byte = 0x80 | self.packet_type.to_byte();
            buf.put_u8(first_byte);
            
            // Version
            if let Some(version) = self.version {
                buf.put_u32(version);
            }
            
            // Destination connection ID
            if let Some(ref dcid) = self.destination_connection_id {
                buf.put_u8(dcid.len() as u8);
                buf.extend_from_slice(dcid);
            } else {
                buf.put_u8(0);
            }
            
            // Source connection ID
            if let Some(ref scid) = self.source_connection_id {
                buf.put_u8(scid.len() as u8);
                buf.extend_from_slice(scid);
            } else {
                buf.put_u8(0);
            }
            
            // Token (for Initial packets)
            if self.packet_type == PacketType::Initial {
                if let Some(ref token) = self.token {
                    buf.put_u8(token.len() as u8);
                    buf.extend_from_slice(token);
                } else {
                    buf.put_u8(0);
                }
            }
            
            // Length
            if let Some(length) = self.length {
                buf.put_u64(length);
            }
        } else {
            // Short header format
            let first_byte = 0x40 | self.packet_type.to_byte();
            buf.put_u8(first_byte);
            
            // Connection ID
            buf.extend_from_slice(&self.connection_id);
        }
        
        // Packet number
        let pn_bytes = self.packet_number.encode(None);
        buf.extend_from_slice(&pn_bytes);
        
        buf.freeze()
    }
    
    /// Decode packet header from bytes
    pub fn decode(data: &[u8]) -> Result<(Self, usize)> {
        if data.is_empty() {
            return Err(QuicError::Packet(PacketError::IncompleteData));
        }
        
        let first_byte = data[0];
        let mut offset = 1;
        
        if (first_byte & 0x80) != 0 {
            // Long header packet
            let packet_type = PacketType::from_byte(first_byte & 0x7F)
                .ok_or(QuicError::Packet(PacketError::UnsupportedType(first_byte)))?;
            
            // Version
            if data.len() < offset + 4 {
                return Err(QuicError::Packet(PacketError::IncompleteData));
            }
            let version = u32::from_be_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);
            offset += 4;
            
            // Destination connection ID
            if data.len() < offset + 1 {
                return Err(QuicError::Packet(PacketError::IncompleteData));
            }
            let dcid_len = data[offset] as usize;
            offset += 1;
            
            if data.len() < offset + dcid_len {
                return Err(QuicError::Packet(PacketError::IncompleteData));
            }
            let destination_connection_id = Bytes::copy_from_slice(&data[offset..offset + dcid_len]);
            offset += dcid_len;
            
            // Source connection ID
            if data.len() < offset + 1 {
                return Err(QuicError::Packet(PacketError::IncompleteData));
            }
            let scid_len = data[offset] as usize;
            offset += 1;
            
            if data.len() < offset + scid_len {
                return Err(QuicError::Packet(PacketError::IncompleteData));
            }
            let source_connection_id = Bytes::copy_from_slice(&data[offset..offset + scid_len]);
            offset += scid_len;
            
            // Token (for Initial packets)
            let token = if packet_type == PacketType::Initial {
                if data.len() < offset + 1 {
                    return Err(QuicError::Packet(PacketError::IncompleteData));
                }
                let token_len = data[offset] as usize;
                offset += 1;
                
                if data.len() < offset + token_len {
                    return Err(QuicError::Packet(PacketError::IncompleteData));
                }
                let token = Bytes::copy_from_slice(&data[offset..offset + token_len]);
                offset += token_len;
                Some(token)
            } else {
                None
            };
            
            // Length
            if data.len() < offset + 8 {
                return Err(QuicError::Packet(PacketError::IncompleteData));
            }
            let length = u64::from_be_bytes([
                data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
                data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]
            ]);
            offset += 8;
            
            // Packet number
            let (packet_number, pn_len) = PacketNumber::decode(&data[offset..])?;
            offset += pn_len;
            
            let header = PacketHeader {
                packet_type,
                connection_id: destination_connection_id.clone(),
                packet_number,
                version: Some(version),
                source_connection_id: Some(source_connection_id),
                destination_connection_id: Some(destination_connection_id),
                token,
                length: Some(length),
            };
            
            Ok((header, offset))
        } else {
            // Short header packet
            let packet_type = PacketType::OneRtt;
            
            // Connection ID (assume 8 bytes for simplicity)
            let connection_id_len = 8;
            if data.len() < offset + connection_id_len {
                return Err(QuicError::Packet(PacketError::IncompleteData));
            }
            let connection_id = Bytes::copy_from_slice(&data[offset..offset + connection_id_len]);
            offset += connection_id_len;
            
            // Packet number
            let (packet_number, pn_len) = PacketNumber::decode(&data[offset..])?;
            offset += pn_len;
            
            let header = PacketHeader {
                packet_type,
                connection_id,
                packet_number,
                version: None,
                source_connection_id: None,
                destination_connection_id: None,
                token: None,
                length: None,
            };
            
            Ok((header, offset))
        }
    }
}

/// QUIC packet
#[derive(Debug, Clone)]
pub struct Packet {
    /// Packet header
    pub header: PacketHeader,
    /// Packet payload
    pub payload: Bytes,
}

impl Packet {
    /// Create a new packet
    pub fn new(header: PacketHeader, payload: Bytes) -> Self {
        Self { header, payload }
    }
    
    /// Get packet size
    pub fn size(&self) -> usize {
        self.header.encode().len() + self.payload.len()
    }
    
    /// Encode packet to bytes
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        
        // Encode header
        let header_bytes = self.header.encode();
        buf.extend_from_slice(&header_bytes);
        
        // Encode payload
        buf.extend_from_slice(&self.payload);
        
        buf.freeze()
    }
    
    /// Decode packet from bytes
    pub fn decode(data: &[u8]) -> Result<Self> {
        let (header, header_len) = PacketHeader::decode(data)?;
        
        if data.len() < header_len {
            return Err(QuicError::Packet(PacketError::IncompleteData));
        }
        
        let payload = Bytes::copy_from_slice(&data[header_len..]);
        
        Ok(Self { header, payload })
    }
    
    /// Check if this packet is encrypted
    pub fn is_encrypted(&self) -> bool {
        match self.header.packet_type {
            PacketType::Initial | PacketType::Handshake => false,
            PacketType::ZeroRtt | PacketType::OneRtt => true,
            PacketType::Retry | PacketType::VersionNegotiation => false,
        }
    }
    
    /// Get packet type
    pub fn packet_type(&self) -> PacketType {
        self.header.packet_type
    }
    
    /// Get connection ID
    pub fn connection_id(&self) -> &Bytes {
        &self.header.connection_id
    }
    
    /// Get packet number
    pub fn packet_number(&self) -> PacketNumber {
        self.header.packet_number
    }
}

/// Packet builder for easier construction
pub struct PacketBuilder {
    packet_type: PacketType,
    connection_id: Option<Bytes>,
    packet_number: Option<PacketNumber>,
    version: Option<u32>,
    source_connection_id: Option<Bytes>,
    destination_connection_id: Option<Bytes>,
    token: Option<Bytes>,
    payload: Option<Bytes>,
}

impl PacketBuilder {
    /// Create a new packet builder
    pub fn new(packet_type: PacketType) -> Self {
        Self {
            packet_type,
            connection_id: None,
            packet_number: None,
            version: None,
            source_connection_id: None,
            destination_connection_id: None,
            token: None,
            payload: None,
        }
    }
    
    /// Set connection ID
    pub fn connection_id(mut self, connection_id: Bytes) -> Self {
        self.connection_id = Some(connection_id);
        self
    }
    
    /// Set packet number
    pub fn packet_number(mut self, packet_number: PacketNumber) -> Self {
        self.packet_number = Some(packet_number);
        self
    }
    
    /// Set version
    pub fn version(mut self, version: u32) -> Self {
        self.version = Some(version);
        self
    }
    
    /// Set source connection ID
    pub fn source_connection_id(mut self, source_connection_id: Bytes) -> Self {
        self.source_connection_id = Some(source_connection_id);
        self
    }
    
    /// Set destination connection ID
    pub fn destination_connection_id(mut self, destination_connection_id: Bytes) -> Self {
        self.destination_connection_id = Some(destination_connection_id);
        self
    }
    
    /// Set token
    pub fn token(mut self, token: Bytes) -> Self {
        self.token = Some(token);
        self
    }
    
    /// Set payload
    pub fn payload(mut self, payload: Bytes) -> Self {
        self.payload = Some(payload);
        self
    }
    
    /// Build the packet
    pub fn build(self) -> Result<Packet> {
        let connection_id = self.connection_id
            .ok_or(QuicError::Packet(PacketError::InvalidHeader))?;
        let packet_number = self.packet_number
            .ok_or(QuicError::Packet(PacketError::InvalidHeader))?;
        let payload = self.payload.unwrap_or_else(|| Bytes::new());
        
        let header = if self.packet_type.is_long_header() {
            let version = self.version.unwrap_or(1);
            let destination_connection_id = self.destination_connection_id
                .unwrap_or_else(|| connection_id.clone());
            let source_connection_id = self.source_connection_id
                .unwrap_or_else(|| Bytes::new());
            
            let mut header = PacketHeader::long_header(
                self.packet_type,
                version,
                destination_connection_id,
                source_connection_id,
                packet_number,
            );
            
            if let Some(token) = self.token {
                header.token = Some(token);
            }
            
            header.length = Some(payload.len() as u64);
            header
        } else {
            PacketHeader::new(self.packet_type, connection_id, packet_number)
        };
        
        Ok(Packet::new(header, payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_packet_type_conversion() {
        assert_eq!(PacketType::Initial.to_byte(), 0x00);
        assert_eq!(PacketType::from_byte(0x00), Some(PacketType::Initial));
        
        assert_eq!(PacketType::OneRtt.to_byte(), 0x04);
        assert_eq!(PacketType::from_byte(0x04), Some(PacketType::OneRtt));
        
        assert_eq!(PacketType::from_byte(0xFF), Some(PacketType::VersionNegotiation));
    }
    
    #[test]
    fn test_packet_number_encoding() {
        let pn = PacketNumber::new(42);
        let encoded = pn.encode(None);
        
        assert_eq!(encoded, vec![42]);
        
        let (decoded, len) = PacketNumber::decode(&encoded).unwrap();
        assert_eq!(decoded, pn);
        assert_eq!(len, 1);
    }
    
    #[test]
    fn test_packet_header_encoding() {
        let connection_id = Bytes::from("test_conn_id");
        let packet_number = PacketNumber::new(100);
        
        let header = PacketHeader::new(
            PacketType::OneRtt,
            connection_id.clone(),
            packet_number,
        );
        
        let encoded = header.encode();
        assert!(!encoded.is_empty());
        
        let (decoded, _) = PacketHeader::decode(&encoded).unwrap();
        assert_eq!(decoded.packet_type, PacketType::OneRtt);
        assert_eq!(decoded.packet_number, packet_number);
    }
    
    #[test]
    fn test_packet_builder() {
        let packet = PacketBuilder::new(PacketType::OneRtt)
            .connection_id(Bytes::from("conn_id"))
            .packet_number(PacketNumber::new(1))
            .payload(Bytes::from("test payload"))
            .build()
            .unwrap();
        
        assert_eq!(packet.packet_type(), PacketType::OneRtt);
        assert_eq!(packet.packet_number(), PacketNumber::new(1));
        assert_eq!(packet.payload, Bytes::from("test payload"));
    }
    
    #[test]
    fn test_packet_serialization() {
        let packet = PacketBuilder::new(PacketType::OneRtt)
            .connection_id(Bytes::from("conn_id"))
            .packet_number(PacketNumber::new(1))
            .payload(Bytes::from("test"))
            .build()
            .unwrap();
        
        let encoded = packet.encode();
        let decoded = Packet::decode(&encoded).unwrap();
        
        assert_eq!(decoded.packet_type(), packet.packet_type());
        assert_eq!(decoded.packet_number(), packet.packet_number());
        assert_eq!(decoded.payload, packet.payload);
    }
}