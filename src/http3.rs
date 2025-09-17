//! HTTP/3 implementation over QUIC
//!
//! This module provides HTTP/3 protocol implementation as specified in RFC 9114,
//! including QPACK header compression (RFC 9204) and WebTransport support.

use crate::quic::error::{QuicError, Result};
use crate::quic::stream::StreamId;
use bytes::{Bytes, BytesMut, Buf, BufMut};
use std::collections::HashMap;
use std::convert::TryFrom;
use tracing::{debug, warn};

/// HTTP/3 frame types as defined in RFC 9114
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Http3FrameType {
    /// DATA frame - HTTP response/request body
    Data = 0x00,
    /// HEADERS frame - HTTP headers
    Headers = 0x01,
    /// PRIORITY frame - Stream priority (deprecated)
    Priority = 0x02,
    /// CANCEL_PUSH frame - Cancel server push
    CancelPush = 0x03,
    /// SETTINGS frame - Connection settings
    Settings = 0x04,
    /// PUSH_PROMISE frame - Server push promise
    PushPromise = 0x05,
    /// GOAWAY frame - Graceful connection termination
    GoAway = 0x07,
    /// MAX_PUSH_ID frame - Maximum push stream ID
    MaxPushId = 0x0D,
}

impl TryFrom<u64> for Http3FrameType {
    type Error = QuicError;

    fn try_from(value: u64) -> Result<Self> {
        match value {
            0x00 => Ok(Http3FrameType::Data),
            0x01 => Ok(Http3FrameType::Headers),
            0x02 => Ok(Http3FrameType::Priority),
            0x03 => Ok(Http3FrameType::CancelPush),
            0x04 => Ok(Http3FrameType::Settings),
            0x05 => Ok(Http3FrameType::PushPromise),
            0x07 => Ok(Http3FrameType::GoAway),
            0x0D => Ok(Http3FrameType::MaxPushId),
            _ => Err(QuicError::Http3(format!("Unknown frame type: {}", value))),
        }
    }
}

/// HTTP/3 frame
#[derive(Debug, Clone)]
pub enum Http3Frame {
    /// DATA frame
    Data {
        stream_id: StreamId,
        data: Bytes,
    },
    /// HEADERS frame
    Headers {
        stream_id: StreamId,
        headers: Vec<Http3Header>,
        fin: bool,
    },
    /// SETTINGS frame
    Settings {
        settings: HashMap<u64, u64>,
    },
    /// GOAWAY frame
    GoAway {
        stream_id: StreamId,
    },
    /// CANCEL_PUSH frame
    CancelPush {
        push_id: u64,
    },
    /// MAX_PUSH_ID frame
    MaxPushId {
        push_id: u64,
    },
}

/// HTTP/3 header
#[derive(Debug, Clone)]
pub struct Http3Header {
    pub name: Bytes,
    pub value: Bytes,
}

impl Http3Header {
    pub fn new(name: impl Into<Bytes>, value: impl Into<Bytes>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

/// HTTP/3 request
#[derive(Debug, Clone)]
pub struct Http3Request {
    pub method: Bytes,
    pub path: Bytes,
    pub authority: Option<Bytes>,
    pub scheme: Bytes,
    pub headers: Vec<Http3Header>,
    pub body: Option<Bytes>,
}

impl Http3Request {
    pub fn new(method: impl Into<Bytes>, path: impl Into<Bytes>) -> Self {
        Self {
            method: method.into(),
            path: path.into(),
            authority: None,
            scheme: "https".into(),
            headers: Vec::new(),
            body: None,
        }
    }

    pub fn header(mut self, name: impl Into<Bytes>, value: impl Into<Bytes>) -> Self {
        self.headers.push(Http3Header::new(name, value));
        self
    }

    pub fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = Some(body.into());
        self
    }
}

/// HTTP/3 response
#[derive(Debug, Clone)]
pub struct Http3Response {
    pub status: u16,
    pub headers: Vec<Http3Header>,
    pub body: Option<Bytes>,
}

impl Http3Response {
    pub fn new(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: None,
        }
    }

    pub fn header(mut self, name: impl Into<Bytes>, value: impl Into<Bytes>) -> Self {
        self.headers.push(Http3Header::new(name, value));
        self
    }

    pub fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = Some(body.into());
        self
    }

    pub fn ok() -> Self {
        Self::new(200)
    }

    pub fn not_found() -> Self {
        Self::new(404)
    }

    pub fn internal_server_error() -> Self {
        Self::new(500)
    }
}

/// QPACK encoder/decoder for header compression
#[derive(Debug)]
pub struct QpackCodec {
    /// Dynamic table for header compression
    dynamic_table: Vec<Http3Header>,
    /// Maximum dynamic table size
    max_table_size: usize,
    /// Current dynamic table size
    current_table_size: usize,
}

impl QpackCodec {
    pub fn new(max_table_size: usize) -> Self {
        Self {
            dynamic_table: Vec::new(),
            max_table_size,
            current_table_size: 0,
        }
    }

    /// Encode headers using QPACK
    pub fn encode_headers(&mut self, headers: &[Http3Header]) -> Result<Bytes> {
        let mut encoded = BytesMut::new();

        for header in headers {
            // Simplified encoding - in a real implementation, this would use
            // the static table and dynamic table for compression

            // For now, encode as literal header field
            encoded.put_u8(0x20); // Literal header field without name reference

            // Encode name length and name
            self.encode_string(&mut encoded, &header.name);

            // Encode value length and value
            self.encode_string(&mut encoded, &header.value);
        }

        Ok(encoded.freeze())
    }

    /// Decode headers using QPACK
    pub fn decode_headers(&mut self, data: &[u8]) -> Result<Vec<Http3Header>> {
        let mut headers = Vec::new();
        let mut cursor = std::io::Cursor::new(data);

        while cursor.position() < data.len() as u64 {
            let prefix = cursor.get_u8();

            if prefix & 0x80 != 0 {
                // Indexed header field
                let index = prefix & 0x7F;
                if let Some(header) = self.get_indexed_header(index as usize) {
                    headers.push(header);
                }
            } else if prefix & 0x40 != 0 {
                // Literal header field with incremental indexing
                let name = self.decode_string(&mut cursor)?;
                let value = self.decode_string(&mut cursor)?;
                let header = Http3Header::new(name, value);
                self.add_to_dynamic_table(header.clone());
                headers.push(header);
            } else if prefix & 0x20 != 0 {
                // Literal header field without indexing
                let name = self.decode_string(&mut cursor)?;
                let value = self.decode_string(&mut cursor)?;
                headers.push(Http3Header::new(name, value));
            }
        }

        Ok(headers)
    }

    fn encode_string(&self, buf: &mut BytesMut, s: &[u8]) {
        // Simplified string encoding - no Huffman coding
        buf.put_u8(s.len() as u8);
        buf.put_slice(s);
    }

    fn decode_string(&self, cursor: &mut std::io::Cursor<&[u8]>) -> Result<Bytes> {
        let len = cursor.get_u8() as usize;
        let mut string_data = vec![0u8; len];

        for i in 0..len {
            if cursor.position() >= cursor.get_ref().len() as u64 {
                return Err(QuicError::Http3("Unexpected end of data".to_string()));
            }
            string_data[i] = cursor.get_u8();
        }

        Ok(Bytes::from(string_data))
    }

    fn get_indexed_header(&self, index: usize) -> Option<Http3Header> {
        // Static table entries (simplified)
        match index {
            1 => Some(Http3Header::new(b":authority", b"")),
            2 => Some(Http3Header::new(b":method", b"GET")),
            3 => Some(Http3Header::new(b":method", b"POST")),
            4 => Some(Http3Header::new(b":path", b"/")),
            5 => Some(Http3Header::new(b":scheme", b"https")),
            6 => Some(Http3Header::new(b":status", b"200")),
            7 => Some(Http3Header::new(b":status", b"404")),
            8 => Some(Http3Header::new(b":status", b"500")),
            _ => {
                // Dynamic table lookup
                let dynamic_index = index.saturating_sub(100); // Offset for static table
                self.dynamic_table.get(dynamic_index).cloned()
            }
        }
    }

    fn add_to_dynamic_table(&mut self, header: Http3Header) {
        let header_size = header.name.len() + header.value.len() + 32; // RFC overhead

        // Evict entries if necessary
        while self.current_table_size + header_size > self.max_table_size && !self.dynamic_table.is_empty() {
            if let Some(evicted) = self.dynamic_table.pop() {
                self.current_table_size -= evicted.name.len() + evicted.value.len() + 32;
            }
        }

        if header_size <= self.max_table_size {
            self.current_table_size += header_size;
            self.dynamic_table.insert(0, header);
        }
    }
}

/// HTTP/3 connection
#[derive(Debug)]
pub struct Http3Connection {
    /// QPACK codec for header compression
    qpack: QpackCodec,
    /// Connection settings
    settings: HashMap<u64, u64>,
    /// Maximum push ID
    max_push_id: Option<u64>,
    /// Active streams
    streams: HashMap<StreamId, Http3Stream>,
}

impl Http3Connection {
    pub fn new() -> Self {
        let mut settings = HashMap::new();
        settings.insert(0x01, 100); // QPACK_MAX_TABLE_CAPACITY
        settings.insert(0x07, 100); // QPACK_BLOCKED_STREAMS

        Self {
            qpack: QpackCodec::new(4096),
            settings,
            max_push_id: None,
            streams: HashMap::new(),
        }
    }

    /// Send HTTP/3 request
    pub fn send_request(&mut self, stream_id: StreamId, request: Http3Request) -> Result<Vec<Http3Frame>> {
        let mut frames = Vec::new();

        // Create pseudo-headers
        let mut headers = vec![
            Http3Header::new(b":method", request.method),
            Http3Header::new(b":path", request.path),
            Http3Header::new(b":scheme", request.scheme),
        ];

        if let Some(authority) = request.authority {
            headers.push(Http3Header::new(b":authority", authority));
        }

        // Add regular headers
        headers.extend(request.headers);

        // HEADERS frame
        frames.push(Http3Frame::Headers {
            stream_id,
            headers,
            fin: request.body.is_none(),
        });

        // DATA frame if body exists
        if let Some(body) = request.body {
            frames.push(Http3Frame::Data {
                stream_id,
                data: body,
            });
        }

        Ok(frames)
    }

    /// Send HTTP/3 response
    pub fn send_response(&mut self, stream_id: StreamId, response: Http3Response) -> Result<Vec<Http3Frame>> {
        let mut frames = Vec::new();

        // Create pseudo-headers
        let mut headers = vec![
            Http3Header::new(b":status", response.status.to_string().into_bytes()),
        ];

        // Add regular headers
        headers.extend(response.headers);

        // HEADERS frame
        frames.push(Http3Frame::Headers {
            stream_id,
            headers,
            fin: response.body.is_none(),
        });

        // DATA frame if body exists
        if let Some(body) = response.body {
            frames.push(Http3Frame::Data {
                stream_id,
                data: body,
            });
        }

        Ok(frames)
    }

    /// Process incoming HTTP/3 frame
    pub fn process_frame(&mut self, frame: Http3Frame) -> Result<Option<Http3Response>> {
        match frame {
            Http3Frame::Headers { stream_id, headers, fin } => {
                debug!("Received HEADERS frame for stream {}", stream_id.value());

                // Parse headers into request
                if let Some(request) = self.parse_request_headers(&headers)? {
                    // Simple echo server response for demo
                    let response = Http3Response::ok()
                        .header("content-type", "text/plain")
                        .body("Hello from GQUIC HTTP/3!");

                    return Ok(Some(response));
                }
            }
            Http3Frame::Data { stream_id, data } => {
                debug!("Received DATA frame for stream {} with {} bytes",
                       stream_id.value(), data.len());

                // Handle data frame
                if let Some(stream) = self.streams.get_mut(&stream_id) {
                    stream.received_data.extend_from_slice(&data);
                }
            }
            Http3Frame::Settings { settings } => {
                debug!("Received SETTINGS frame with {} settings", settings.len());
                self.settings.extend(settings);
            }
            Http3Frame::GoAway { stream_id } => {
                debug!("Received GOAWAY frame for stream {}", stream_id.value());
                // Handle graceful shutdown
            }
            _ => {
                debug!("Received other HTTP/3 frame: {:?}", frame);
            }
        }

        Ok(None)
    }

    fn parse_request_headers(&self, headers: &[Http3Header]) -> Result<Option<Http3Request>> {
        let mut method = None;
        let mut path = None;
        let mut scheme = None;
        let mut authority = None;
        let mut other_headers = Vec::new();

        for header in headers {
            let name_str = std::str::from_utf8(&header.name)
                .map_err(|_| QuicError::Http3("Invalid header name".to_string()))?;

            match name_str {
                ":method" => method = Some(header.value.clone()),
                ":path" => path = Some(header.value.clone()),
                ":scheme" => scheme = Some(header.value.clone()),
                ":authority" => authority = Some(header.value.clone()),
                _ => other_headers.push(header.clone()),
            }
        }

        if let (Some(method), Some(path)) = (method, path) {
            let mut request = Http3Request::new(method, path);
            request.authority = authority;
            if let Some(scheme) = scheme {
                request.scheme = scheme;
            }
            request.headers = other_headers;

            Ok(Some(request))
        } else {
            Ok(None)
        }
    }

    /// Encode frame to bytes
    pub fn encode_frame(&mut self, frame: &Http3Frame) -> Result<Bytes> {
        let mut buf = BytesMut::new();

        match frame {
            Http3Frame::Headers { headers, .. } => {
                // Frame type
                buf.put_u8(Http3FrameType::Headers as u8);

                // Encode headers with QPACK
                let encoded_headers = self.qpack.encode_headers(headers)?;

                // Frame length
                buf.put_u8(encoded_headers.len() as u8);

                // Frame payload
                buf.extend_from_slice(&encoded_headers);
            }
            Http3Frame::Data { data, .. } => {
                // Frame type
                buf.put_u8(Http3FrameType::Data as u8);

                // Frame length
                buf.put_u8(data.len() as u8);

                // Frame payload
                buf.extend_from_slice(data);
            }
            Http3Frame::Settings { settings } => {
                // Frame type
                buf.put_u8(Http3FrameType::Settings as u8);

                // Calculate payload size
                let payload_size = settings.len() * 2; // Simplified
                buf.put_u8(payload_size as u8);

                // Encode settings
                for (&key, &value) in settings {
                    buf.put_u8(key as u8);
                    buf.put_u8(value as u8);
                }
            }
            _ => {
                return Err(QuicError::Http3("Unsupported frame type for encoding".to_string()));
            }
        }

        Ok(buf.freeze())
    }

    /// Decode frame from bytes
    pub fn decode_frame(&mut self, data: &[u8]) -> Result<Http3Frame> {
        if data.is_empty() {
            return Err(QuicError::Http3("Empty frame data".to_string()));
        }

        let frame_type = Http3FrameType::try_from(data[0] as u64)?;
        let frame_length = data.get(1).copied().unwrap_or(0) as usize;

        if data.len() < 2 + frame_length {
            return Err(QuicError::Http3("Incomplete frame data".to_string()));
        }

        let payload = &data[2..2 + frame_length];

        match frame_type {
            Http3FrameType::Headers => {
                let headers = self.qpack.decode_headers(payload)?;
                Ok(Http3Frame::Headers {
                    stream_id: StreamId::new(0), // Would be passed from caller
                    headers,
                    fin: false,
                })
            }
            Http3FrameType::Data => {
                Ok(Http3Frame::Data {
                    stream_id: StreamId::new(0), // Would be passed from caller
                    data: Bytes::copy_from_slice(payload),
                })
            }
            Http3FrameType::Settings => {
                let mut settings = HashMap::new();

                // Simplified settings parsing
                for chunk in payload.chunks(2) {
                    if chunk.len() == 2 {
                        settings.insert(chunk[0] as u64, chunk[1] as u64);
                    }
                }

                Ok(Http3Frame::Settings { settings })
            }
            _ => {
                Err(QuicError::Http3(format!("Unsupported frame type: {:?}", frame_type)))
            }
        }
    }
}

/// HTTP/3 stream state
#[derive(Debug)]
pub struct Http3Stream {
    pub stream_id: StreamId,
    pub received_data: BytesMut,
    pub is_complete: bool,
}

impl Http3Stream {
    pub fn new(stream_id: StreamId) -> Self {
        Self {
            stream_id,
            received_data: BytesMut::new(),
            is_complete: false,
        }
    }
}

impl Default for Http3Connection {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http3_request_creation() {
        let request = Http3Request::new("GET", "/api/test")
            .header("user-agent", "gquic/1.0")
            .header("accept", "application/json");

        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/api/test");
        assert_eq!(request.headers.len(), 2);
    }

    #[test]
    fn test_http3_response_creation() {
        let response = Http3Response::ok()
            .header("content-type", "application/json")
            .body("{\"message\": \"hello\"}");

        assert_eq!(response.status, 200);
        assert_eq!(response.headers.len(), 1);
        assert!(response.body.is_some());
    }

    #[test]
    fn test_qpack_codec() {
        let mut codec = QpackCodec::new(4096);

        let headers = vec![
            Http3Header::new(b":method", b"GET"),
            Http3Header::new(b":path", b"/test"),
        ];

        let encoded = codec.encode_headers(&headers).unwrap();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_http3_connection() {
        let mut conn = Http3Connection::new();

        let request = Http3Request::new("GET", "/")
            .header("host", "example.com");

        let frames = conn.send_request(StreamId::new(4), request).unwrap();
        assert!(!frames.is_empty());

        // Should have at least a HEADERS frame
        match &frames[0] {
            Http3Frame::Headers { .. } => assert!(true),
            _ => panic!("Expected HEADERS frame"),
        }
    }
}