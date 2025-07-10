// HTTP/3 frame types according to RFC 9114

use bytes::{Bytes, BytesMut, Buf, BufMut};
use std::collections::HashMap;

/// HTTP/3 frame types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Http3FrameType {
    Data = 0x00,
    Headers = 0x01,
    CancelPush = 0x03,
    Settings = 0x04,
    PushPromise = 0x05,
    GoAway = 0x07,
    MaxPushId = 0x0d,
    DuplicatePush = 0x0e,
    // QPACK frames
    QpackInsertWithNameReference = 0x80,
    QpackInsertWithoutNameReference = 0x40,
    QpackDuplicate = 0x00,
    QpackDynamicTableSizeUpdate = 0x20,
}

/// HTTP/3 frame structure
#[derive(Debug, Clone)]
pub enum Http3Frame {
    Data {
        data: Bytes,
    },
    Headers {
        headers: Bytes, // QPACK-encoded headers
    },
    Settings {
        settings: HashMap<u64, u64>,
    },
    GoAway {
        stream_id: u64,
    },
    MaxPushId {
        push_id: u64,
    },
    CancelPush {
        push_id: u64,
    },
    PushPromise {
        push_id: u64,
        headers: Bytes,
    },
    DuplicatePush {
        push_id: u64,
    },
    // QPACK frames
    QpackInsertWithNameReference {
        name_index: u64,
        value: Bytes,
    },
    QpackInsertWithoutNameReference {
        name: Bytes,
        value: Bytes,
    },
    QpackDuplicate {
        index: u64,
    },
    QpackDynamicTableSizeUpdate {
        max_size: u64,
    },
}

impl Http3Frame {
    /// Encode frame to bytes
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        
        match self {
            Http3Frame::Data { data } => {
                encode_varint(&mut buf, Http3FrameType::Data as u64);
                encode_varint(&mut buf, data.len() as u64);
                buf.extend_from_slice(data);
            }
            Http3Frame::Headers { headers } => {
                encode_varint(&mut buf, Http3FrameType::Headers as u64);
                encode_varint(&mut buf, headers.len() as u64);
                buf.extend_from_slice(headers);
            }
            Http3Frame::Settings { settings } => {
                encode_varint(&mut buf, Http3FrameType::Settings as u64);
                
                // Calculate payload length
                let payload_len = settings.iter()
                    .map(|(k, v)| varint_len(*k) + varint_len(*v))
                    .sum::<usize>();
                
                encode_varint(&mut buf, payload_len as u64);
                
                for (key, value) in settings {
                    encode_varint(&mut buf, *key);
                    encode_varint(&mut buf, *value);
                }
            }
            Http3Frame::GoAway { stream_id } => {
                encode_varint(&mut buf, Http3FrameType::GoAway as u64);
                encode_varint(&mut buf, varint_len(*stream_id) as u64);
                encode_varint(&mut buf, *stream_id);
            }
            Http3Frame::MaxPushId { push_id } => {
                encode_varint(&mut buf, Http3FrameType::MaxPushId as u64);
                encode_varint(&mut buf, varint_len(*push_id) as u64);
                encode_varint(&mut buf, *push_id);
            }
            Http3Frame::CancelPush { push_id } => {
                encode_varint(&mut buf, Http3FrameType::CancelPush as u64);
                encode_varint(&mut buf, varint_len(*push_id) as u64);
                encode_varint(&mut buf, *push_id);
            }
            Http3Frame::PushPromise { push_id, headers } => {
                encode_varint(&mut buf, Http3FrameType::PushPromise as u64);
                let payload_len = varint_len(*push_id) + headers.len();
                encode_varint(&mut buf, payload_len as u64);
                encode_varint(&mut buf, *push_id);
                buf.extend_from_slice(headers);
            }
            Http3Frame::DuplicatePush { push_id } => {
                encode_varint(&mut buf, Http3FrameType::DuplicatePush as u64);
                encode_varint(&mut buf, varint_len(*push_id) as u64);
                encode_varint(&mut buf, *push_id);
            }
            // QPACK frames would be implemented here
            _ => {
                // TODO: Implement QPACK frame encoding
            }
        }
        
        buf.freeze()
    }
    
    /// Decode frame from bytes
    pub fn decode(data: &mut &[u8]) -> Result<(Self, usize), super::error::Http3Error> {
        if data.is_empty() {
            return Err(super::error::Http3Error::ProtocolError("Empty frame data".into()));
        }
        
        let original_len = data.len();
        let frame_type = decode_varint(data)?;
        let frame_length = decode_varint(data)?;
        
        if data.len() < frame_length as usize {
            return Err(super::error::Http3Error::ProtocolError("Insufficient frame data".into()));
        }
        
        let frame = match frame_type {
            0x00 => { // DATA
                let frame_data = Bytes::copy_from_slice(&data[..frame_length as usize]);
                data = &data[frame_length as usize..];
                Http3Frame::Data { data: frame_data }
            }
            0x01 => { // HEADERS
                let headers = Bytes::copy_from_slice(&data[..frame_length as usize]);
                data = &data[frame_length as usize..];
                Http3Frame::Headers { headers }
            }
            0x04 => { // SETTINGS
                let mut settings = HashMap::new();
                let mut remaining = frame_length as usize;
                let mut frame_data = &data[..remaining];
                
                while !frame_data.is_empty() && remaining > 0 {
                    let key = decode_varint(&mut frame_data)?;
                    let value = decode_varint(&mut frame_data)?;
                    settings.insert(key, value);
                    remaining = frame_data.len();
                }
                
                data = &data[frame_length as usize..];
                Http3Frame::Settings { settings }
            }
            0x07 => { // GOAWAY
                let mut frame_data = &data[..frame_length as usize];
                let stream_id = decode_varint(&mut frame_data)?;
                data = &data[frame_length as usize..];
                Http3Frame::GoAway { stream_id }
            }
            0x0d => { // MAX_PUSH_ID
                let mut frame_data = &data[..frame_length as usize];
                let push_id = decode_varint(&mut frame_data)?;
                data = &data[frame_length as usize..];
                Http3Frame::MaxPushId { push_id }
            }
            0x03 => { // CANCEL_PUSH
                let mut frame_data = &data[..frame_length as usize];
                let push_id = decode_varint(&mut frame_data)?;
                data = &data[frame_length as usize..];
                Http3Frame::CancelPush { push_id }
            }
            0x05 => { // PUSH_PROMISE
                let mut frame_data = &data[..frame_length as usize];
                let push_id = decode_varint(&mut frame_data)?;
                let headers = Bytes::copy_from_slice(frame_data);
                data = &data[frame_length as usize..];
                Http3Frame::PushPromise { push_id, headers }
            }
            _ => {
                // Skip unknown frame types (forward compatibility)
                data = &data[frame_length as usize..];
                return Err(super::error::Http3Error::ProtocolError(format!("Unknown frame type: {}", frame_type)));
            }
        };
        
        let consumed = original_len - data.len();
        Ok((frame, consumed))
    }
}

/// HTTP/3 settings identifiers
pub mod settings {
    pub const QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
    pub const MAX_FIELD_SECTION_SIZE: u64 = 0x06;
    pub const QPACK_BLOCKED_STREAMS: u64 = 0x07;
    pub const ENABLE_CONNECT_PROTOCOL: u64 = 0x08;
    pub const H3_DATAGRAM: u64 = 0x33;
}

// QUIC variable-length integer encoding/decoding helpers
fn encode_varint(buf: &mut BytesMut, value: u64) {
    if value < 64 {
        buf.put_u8(value as u8);
    } else if value < 16384 {
        buf.put_u8(0x40 | (value >> 8) as u8);
        buf.put_u8((value & 0xff) as u8);
    } else if value < 1073741824 {
        buf.put_u8(0x80 | (value >> 24) as u8);
        buf.put_u8((value >> 16) as u8);
        buf.put_u8((value >> 8) as u8);
        buf.put_u8((value & 0xff) as u8);
    } else {
        buf.put_u8(0xc0 | (value >> 56) as u8);
        buf.put_u32((value >> 24) as u32);
        buf.put_u32((value & 0xffffff) as u32);
    }
}

fn decode_varint(data: &mut &[u8]) -> Result<u64, super::error::Http3Error> {
    if data.is_empty() {
        return Err(super::error::Http3Error::ProtocolError("Empty varint data".into()));
    }
    
    let first_byte = data[0];
    *data = &data[1..];
    
    match first_byte >> 6 {
        0 => Ok(first_byte as u64),
        1 => {
            if data.is_empty() {
                return Err(super::error::Http3Error::ProtocolError("Incomplete varint".into()));
            }
            let second_byte = data[0];
            *data = &data[1..];
            Ok(((first_byte & 0x3f) as u64) << 8 | second_byte as u64)
        }
        2 => {
            if data.len() < 3 {
                return Err(super::error::Http3Error::ProtocolError("Incomplete varint".into()));
            }
            let value = ((first_byte & 0x3f) as u64) << 24
                | (data[0] as u64) << 16
                | (data[1] as u64) << 8
                | data[2] as u64;
            *data = &data[3..];
            Ok(value)
        }
        3 => {
            if data.len() < 7 {
                return Err(super::error::Http3Error::ProtocolError("Incomplete varint".into()));
            }
            let value = ((first_byte & 0x3f) as u64) << 56
                | (data[0] as u64) << 48
                | (data[1] as u64) << 40
                | (data[2] as u64) << 32
                | (data[3] as u64) << 24
                | (data[4] as u64) << 16
                | (data[5] as u64) << 8
                | data[6] as u64;
            *data = &data[7..];
            Ok(value)
        }
        _ => unreachable!(),
    }
}

fn varint_len(value: u64) -> usize {
    if value < 64 {
        1
    } else if value < 16384 {
        2
    } else if value < 1073741824 {
        4
    } else {
        8
    }
}
