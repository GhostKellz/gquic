use bytes::{Bytes, BytesMut, Buf, BufMut};
use crate::quic::stream::StreamId;

/// QUIC frame types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Padding = 0x00,
    Ping = 0x01,
    Ack = 0x02,
    ResetStream = 0x04,
    StopSending = 0x05,
    Crypto = 0x06,
    NewToken = 0x07,
    Stream = 0x08,
    MaxData = 0x10,
    MaxStreamData = 0x11,
    MaxStreams = 0x12,
    DataBlocked = 0x14,
    StreamDataBlocked = 0x15,
    StreamsBlocked = 0x16,
    NewConnectionId = 0x18,
    RetireConnectionId = 0x19,
    PathChallenge = 0x1a,
    PathResponse = 0x1b,
    ConnectionClose = 0x1c,
    HandshakeDone = 0x1e,
}

impl FrameType {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(FrameType::Padding),
            0x01 => Some(FrameType::Ping),
            0x02..=0x03 => Some(FrameType::Ack),
            0x04 => Some(FrameType::ResetStream),
            0x05 => Some(FrameType::StopSending),
            0x06 => Some(FrameType::Crypto),
            0x07 => Some(FrameType::NewToken),
            0x08..=0x0f => Some(FrameType::Stream),
            0x10 => Some(FrameType::MaxData),
            0x11 => Some(FrameType::MaxStreamData),
            0x12..=0x13 => Some(FrameType::MaxStreams),
            0x14 => Some(FrameType::DataBlocked),
            0x15 => Some(FrameType::StreamDataBlocked),
            0x16..=0x17 => Some(FrameType::StreamsBlocked),
            0x18 => Some(FrameType::NewConnectionId),
            0x19 => Some(FrameType::RetireConnectionId),
            0x1a => Some(FrameType::PathChallenge),
            0x1b => Some(FrameType::PathResponse),
            0x1c..=0x1d => Some(FrameType::ConnectionClose),
            0x1e => Some(FrameType::HandshakeDone),
            _ => None,
        }
    }
}

/// QUIC frames
#[derive(Debug, Clone)]
pub enum Frame {
    Padding {
        length: usize,
    },
    Ping,
    Ack {
        largest_acknowledged: u64,
        ack_delay: u64,
        ack_ranges: Vec<(u64, u64)>,
    },
    ResetStream {
        stream_id: StreamId,
        application_error_code: u64,
        final_size: u64,
    },
    StopSending {
        stream_id: StreamId,
        application_error_code: u64,
    },
    Crypto {
        offset: u64,
        data: Bytes,
    },
    NewToken {
        token: Bytes,
    },
    Stream {
        stream_id: StreamId,
        offset: u64,
        data: Bytes,
        fin: bool,
    },
    MaxData {
        maximum_data: u64,
    },
    MaxStreamData {
        stream_id: StreamId,
        maximum_stream_data: u64,
    },
    MaxStreams {
        maximum_streams: u64,
        bidirectional: bool,
    },
    DataBlocked {
        maximum_data: u64,
    },
    StreamDataBlocked {
        stream_id: StreamId,
        maximum_stream_data: u64,
    },
    StreamsBlocked {
        maximum_streams: u64,
        bidirectional: bool,
    },
    NewConnectionId {
        sequence_number: u64,
        retire_prior_to: u64,
        connection_id: Bytes,
        stateless_reset_token: [u8; 16],
    },
    RetireConnectionId {
        sequence_number: u64,
    },
    PathChallenge {
        data: [u8; 8],
    },
    PathResponse {
        data: [u8; 8],
    },
    ConnectionClose {
        error_code: u64,
        frame_type: Option<u64>,
        reason_phrase: String,
    },
    HandshakeDone,
}

impl Frame {
    /// Encode frame to bytes
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        
        match self {
            Frame::Padding { length } => {
                buf.put_u8(FrameType::Padding as u8);
                buf.resize(buf.len() + length, 0);
            }
            Frame::Ping => {
                buf.put_u8(FrameType::Ping as u8);
            }
            Frame::Stream { stream_id, offset, data, fin } => {
                let mut frame_type = FrameType::Stream as u8;
                if *fin {
                    frame_type |= 0x01; // FIN bit
                }
                if *offset > 0 {
                    frame_type |= 0x04; // OFF bit
                }
                frame_type |= 0x02; // LEN bit (we always include length)
                
                buf.put_u8(frame_type);
                encode_varint(&mut buf, stream_id.value());
                if *offset > 0 {
                    encode_varint(&mut buf, *offset);
                }
                encode_varint(&mut buf, data.len() as u64);
                buf.extend_from_slice(data);
            }
            Frame::Crypto { offset, data } => {
                buf.put_u8(FrameType::Crypto as u8);
                encode_varint(&mut buf, *offset);
                encode_varint(&mut buf, data.len() as u64);
                buf.extend_from_slice(data);
            }
            Frame::ConnectionClose { error_code, frame_type, reason_phrase } => {
                buf.put_u8(FrameType::ConnectionClose as u8);
                encode_varint(&mut buf, *error_code);
                if let Some(ft) = frame_type {
                    encode_varint(&mut buf, *ft);
                } else {
                    encode_varint(&mut buf, 0);
                }
                encode_varint(&mut buf, reason_phrase.len() as u64);
                buf.extend_from_slice(reason_phrase.as_bytes());
            }
            // Add other frame encodings as needed
            _ => {
                // Placeholder for other frame types
                buf.put_u8(FrameType::Ping as u8);
            }
        }
        
        buf.freeze()
    }
    
    /// Decode frame from bytes
    pub fn decode(mut data: &[u8]) -> Result<(Self, usize), super::error::QuicError> {
        if data.is_empty() {
            return Err(super::error::QuicError::Protocol("Empty frame data".to_string()));
        }
        
        let original_len = data.len();
        let frame_type_byte = data[0];
        data = &data[1..];
        
        let frame_type = FrameType::from_byte(frame_type_byte)
            .ok_or_else(|| super::error::QuicError::Protocol(format!("Unknown frame type: {:#x}", frame_type_byte)))?;
        
        let frame = match frame_type {
            FrameType::Padding => {
                // Count consecutive padding bytes
                let mut length = 1;
                while !data.is_empty() && data[0] == 0x00 {
                    length += 1;
                    data = &data[1..];
                }
                Frame::Padding { length }
            }
            FrameType::Ping => Frame::Ping,
            FrameType::Stream => {
                let (stream_id, consumed) = decode_varint(data)?;
                data = &data[consumed..];
                
                let has_offset = (frame_type_byte & 0x04) != 0;
                let has_length = (frame_type_byte & 0x02) != 0;
                let fin = (frame_type_byte & 0x01) != 0;
                
                let offset = if has_offset {
                    let (offset, consumed) = decode_varint(data)?;
                    data = &data[consumed..];
                    offset
                } else {
                    0
                };
                
                let stream_data = if has_length {
                    let (length, consumed) = decode_varint(data)?;
                    data = &data[consumed..];
                    if data.len() < length as usize {
                        return Err(super::error::QuicError::Protocol("Insufficient stream data".to_string()));
                    }
                    let stream_data = Bytes::copy_from_slice(&data[..length as usize]);
                    data = &data[length as usize..];
                    stream_data
                } else {
                    // Use all remaining data
                    let stream_data = Bytes::copy_from_slice(data);
                    data = &[];
                    stream_data
                };
                
                Frame::Stream {
                    stream_id: StreamId::new(stream_id),
                    offset,
                    data: stream_data,
                    fin,
                }
            }
            _ => {
                return Err(super::error::QuicError::Protocol(format!("Unimplemented frame type: {:?}", frame_type)));
            }
        };
        
        let consumed = original_len - data.len();
        Ok((frame, consumed))
    }
}

// QUIC variable-length integer encoding/decoding
fn encode_varint(buf: &mut BytesMut, mut value: u64) {
    if value < 64 {
        buf.put_u8(value as u8);
    } else if value < 16384 {
        buf.put_u16(0x4000 | (value as u16));
    } else if value < 1073741824 {
        buf.put_u32(0x80000000 | (value as u32));
    } else {
        buf.put_u64(0xc000000000000000 | value);
    }
}

fn decode_varint(data: &[u8]) -> Result<(u64, usize), super::error::QuicError> {
    if data.is_empty() {
        return Err(super::error::QuicError::Protocol("Empty varint data".to_string()));
    }
    
    let first_byte = data[0];
    let length_bits = first_byte >> 6;
    
    match length_bits {
        0 => Ok((first_byte as u64, 1)),
        1 => {
            if data.len() < 2 {
                return Err(super::error::QuicError::Protocol("Insufficient varint data".to_string()));
            }
            let value = ((first_byte & 0x3f) as u64) << 8 | data[1] as u64;
            Ok((value, 2))
        }
        2 => {
            if data.len() < 4 {
                return Err(super::error::QuicError::Protocol("Insufficient varint data".to_string()));
            }
            let value = ((first_byte & 0x3f) as u64) << 24
                | (data[1] as u64) << 16
                | (data[2] as u64) << 8
                | data[3] as u64;
            Ok((value, 4))
        }
        3 => {
            if data.len() < 8 {
                return Err(super::error::QuicError::Protocol("Insufficient varint data".to_string()));
            }
            let value = ((first_byte & 0x3f) as u64) << 56
                | (data[1] as u64) << 48
                | (data[2] as u64) << 40
                | (data[3] as u64) << 32
                | (data[4] as u64) << 24
                | (data[5] as u64) << 16
                | (data[6] as u64) << 8
                | data[7] as u64;
            Ok((value, 8))
        }
        _ => unreachable!(),
    }
}