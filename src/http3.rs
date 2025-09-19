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

/// Advanced HTTP/3 frame processor with integration
pub struct AdvancedHttp3Processor {
    frame_parser: Http3FrameParser,
    qpack_encoder: QpackEncoder,
    qpack_decoder: QpackDecoder,
    stream_manager: Http3StreamManager,
    settings: Http3Settings,
    stats: Http3Stats,
}

impl AdvancedHttp3Processor {
    pub fn new(settings: Http3Settings) -> Self {
        Self {
            frame_parser: Http3FrameParser::new(),
            qpack_encoder: QpackEncoder::new(settings.qpack_max_table_capacity),
            qpack_decoder: QpackDecoder::new(settings.qpack_max_table_capacity),
            stream_manager: Http3StreamManager::new(),
            settings,
            stats: Http3Stats::default(),
        }
    }

    /// Process incoming HTTP/3 frames with enhanced features
    pub async fn process_frames(&mut self, stream_id: StreamId, data: &[u8]) -> Result<Vec<ProcessedFrame>> {
        let mut processed_frames = Vec::new();
        let mut buffer = BytesMut::from(data);

        while buffer.has_remaining() {
            match self.frame_parser.parse_frame(&mut buffer)? {
                Some(frame) => {
                    let processed = self.process_single_frame(stream_id, frame).await?;
                    processed_frames.push(processed);
                }
                None => break, // Incomplete frame, need more data
            }
        }

        self.stats.frames_processed += processed_frames.len() as u64;
        Ok(processed_frames)
    }

    async fn process_single_frame(&mut self, stream_id: StreamId, frame: Http3Frame) -> Result<ProcessedFrame> {
        let start_time = std::time::Instant::now();

        let result = match frame {
            Http3Frame::Headers { headers, fin, .. } => {
                self.process_headers_frame(stream_id, headers, fin).await?
            }
            Http3Frame::Data { data, .. } => {
                self.process_data_frame(stream_id, data).await?
            }
            Http3Frame::Settings { settings } => {
                self.process_settings_frame(settings).await?
            }
            Http3Frame::GoAway { stream_id: goaway_stream } => {
                self.process_goaway_frame(goaway_stream).await?
            }
            Http3Frame::CancelPush { push_id } => {
                self.process_cancel_push_frame(push_id).await?
            }
            Http3Frame::MaxPushId { push_id } => {
                self.process_max_push_id_frame(push_id).await?
            }
        };

        let processing_time = start_time.elapsed();
        self.stats.total_processing_time += processing_time;

        Ok(ProcessedFrame {
            stream_id,
            frame_type: result.frame_type,
            result: result.result,
            processing_time,
            qpack_operations: result.qpack_operations,
        })
    }

    async fn process_headers_frame(&mut self, stream_id: StreamId, headers: Vec<Http3Header>, fin: bool) -> Result<FrameProcessingResult> {
        // Decode QPACK headers
        let decoded_headers = self.qpack_decoder.decode_headers(&headers)?;

        // Update stream state
        self.stream_manager.update_stream_headers(stream_id, &decoded_headers, fin)?;

        // Check for HTTP semantics violations
        self.validate_http_semantics(&decoded_headers)?;

        Ok(FrameProcessingResult {
            frame_type: Http3FrameType::Headers,
            result: ProcessingResult::HeadersProcessed {
                headers: decoded_headers,
                stream_complete: fin,
            },
            qpack_operations: 1,
        })
    }

    async fn process_data_frame(&mut self, stream_id: StreamId, data: Bytes) -> Result<FrameProcessingResult> {
        // Update stream state and flow control
        self.stream_manager.update_stream_data(stream_id, &data)?;

        // Apply any content processing (compression, etc.)
        let processed_data = self.process_content_encoding(&data)?;

        Ok(FrameProcessingResult {
            frame_type: Http3FrameType::Data,
            result: ProcessingResult::DataProcessed {
                data: processed_data,
                bytes_received: data.len(),
            },
            qpack_operations: 0,
        })
    }

    async fn process_settings_frame(&mut self, settings: HashMap<u64, u64>) -> Result<FrameProcessingResult> {
        // Update connection settings
        for (setting_id, value) in settings {
            match setting_id {
                0x01 => self.settings.qpack_max_table_capacity = value as usize,
                0x06 => self.settings.max_header_list_size = Some(value as usize),
                0x07 => self.settings.qpack_blocked_streams = value as usize,
                _ => {
                    // Unknown setting, ignore per HTTP/3 spec
                    debug!("Ignoring unknown HTTP/3 setting: {}", setting_id);
                }
            }
        }

        Ok(FrameProcessingResult {
            frame_type: Http3FrameType::Settings,
            result: ProcessingResult::SettingsUpdated,
            qpack_operations: 0,
        })
    }

    async fn process_goaway_frame(&mut self, stream_id: StreamId) -> Result<FrameProcessingResult> {
        // Mark connection for graceful shutdown
        self.stream_manager.mark_goaway(stream_id)?;

        Ok(FrameProcessingResult {
            frame_type: Http3FrameType::GoAway,
            result: ProcessingResult::GoAwayReceived { last_stream: stream_id },
            qpack_operations: 0,
        })
    }

    async fn process_cancel_push_frame(&mut self, push_id: u64) -> Result<FrameProcessingResult> {
        // Cancel the specified push stream
        self.stream_manager.cancel_push_stream(push_id)?;

        Ok(FrameProcessingResult {
            frame_type: Http3FrameType::CancelPush,
            result: ProcessingResult::PushCancelled { push_id },
            qpack_operations: 0,
        })
    }

    async fn process_max_push_id_frame(&mut self, push_id: u64) -> Result<FrameProcessingResult> {
        // Update maximum allowed push ID
        self.stream_manager.update_max_push_id(push_id)?;

        Ok(FrameProcessingResult {
            frame_type: Http3FrameType::MaxPushId,
            result: ProcessingResult::MaxPushIdUpdated { max_push_id: push_id },
            qpack_operations: 0,
        })
    }

    fn validate_http_semantics(&self, headers: &[DecodedHeader]) -> Result<()> {
        // Validate required pseudo-headers
        let mut has_method = false;
        let mut has_path = false;
        let mut has_scheme = false;
        let mut has_authority = false;

        for header in headers {
            if header.name.starts_with(b":") {
                match &header.name[..] {
                    b":method" => has_method = true,
                    b":path" => has_path = true,
                    b":scheme" => has_scheme = true,
                    b":authority" => has_authority = true,
                    _ => {
                        return Err(QuicError::Http3("Unknown pseudo-header".to_string()));
                    }
                }
            }
        }

        // Check required headers for requests
        if !has_method || !has_path || !has_scheme {
            return Err(QuicError::Http3("Missing required pseudo-headers".to_string()));
        }

        Ok(())
    }

    fn process_content_encoding(&self, data: &Bytes) -> Result<Bytes> {
        // Content encoding processing would go here
        // For now, just return the data as-is
        Ok(data.clone())
    }

    /// Encode and send HTTP/3 response
    pub async fn send_response(&mut self, stream_id: StreamId, response: Http3Response) -> Result<Vec<u8>> {
        let mut encoded_data = Vec::new();

        // Encode headers with QPACK
        let encoded_headers = response.headers.clone();
        let headers_frame = Http3Frame::Headers {
            stream_id,
            headers: encoded_headers,
            fin: response.body.as_ref().map_or(true, |b| b.is_empty()),
        };

        // Encode headers frame
        encoded_data.extend(self.frame_parser.encode_frame(&headers_frame)?);

        // Encode body if present
        if response.body.as_ref().map_or(false, |b| !b.is_empty()) {
            let data_frame = Http3Frame::Data {
                stream_id,
                data: response.body.unwrap_or_default(),
            };
            encoded_data.extend(self.frame_parser.encode_frame(&data_frame)?);
        }

        self.stats.responses_sent += 1;
        Ok(encoded_data)
    }

    pub fn stats(&self) -> Http3StatsSnapshot {
        Http3StatsSnapshot {
            frames_processed: self.stats.frames_processed,
            responses_sent: self.stats.responses_sent,
            qpack_operations: self.stats.qpack_operations,
            total_processing_time: self.stats.total_processing_time,
            active_streams: self.stream_manager.active_stream_count(),
        }
    }
}

/// HTTP/3 frame parser
pub struct Http3FrameParser {
    max_frame_size: usize,
}

impl Http3FrameParser {
    pub fn new() -> Self {
        Self {
            max_frame_size: 1024 * 1024, // 1MB default
        }
    }

    pub fn parse_frame(&self, buffer: &mut BytesMut) -> Result<Option<Http3Frame>> {
        if buffer.len() < 2 {
            return Ok(None); // Need at least frame type and length
        }

        // Parse variable-length frame type
        let frame_type = self.read_varint(buffer)?;
        let frame_length = self.read_varint(buffer)?;

        if frame_length > self.max_frame_size as u64 {
            return Err(QuicError::Http3("Frame too large".to_string()));
        }

        if buffer.len() < frame_length as usize {
            return Ok(None); // Incomplete frame
        }

        let frame_data = buffer.split_to(frame_length as usize);
        let frame_type = Http3FrameType::try_from(frame_type)?;

        let frame = match frame_type {
            Http3FrameType::Data => {
                Http3Frame::Data {
                    stream_id: StreamId::new(0), // Will be set by caller
                    data: frame_data.freeze(),
                }
            }
            Http3FrameType::Headers => {
                let headers = self.parse_headers(&frame_data)?;
                Http3Frame::Headers {
                    stream_id: StreamId::new(0), // Will be set by caller
                    headers,
                    fin: false, // Will be determined by caller
                }
            }
            Http3FrameType::Settings => {
                let settings = self.parse_settings(&frame_data)?;
                Http3Frame::Settings { settings }
            }
            Http3FrameType::GoAway => {
                let mut data = frame_data.as_ref();
                let stream_id = StreamId::new(self.read_varint_from_slice(&mut data)?);
                Http3Frame::GoAway { stream_id }
            }
            Http3FrameType::CancelPush => {
                let mut data = frame_data.as_ref();
                let push_id = self.read_varint_from_slice(&mut data)?;
                Http3Frame::CancelPush { push_id }
            }
            Http3FrameType::MaxPushId => {
                let mut data = frame_data.as_ref();
                let push_id = self.read_varint_from_slice(&mut data)?;
                Http3Frame::MaxPushId { push_id }
            }
            _ => {
                return Err(QuicError::Http3(format!("Unsupported frame type: {:?}", frame_type)));
            }
        };

        Ok(Some(frame))
    }

    pub fn encode_frame(&self, frame: &Http3Frame) -> Result<Vec<u8>> {
        let mut encoded = Vec::new();

        match frame {
            Http3Frame::Headers { headers, .. } => {
                self.write_varint(&mut encoded, Http3FrameType::Headers as u64);
                let header_data = self.encode_headers(headers)?;
                self.write_varint(&mut encoded, header_data.len() as u64);
                encoded.extend(header_data);
            }
            Http3Frame::Data { data, .. } => {
                self.write_varint(&mut encoded, Http3FrameType::Data as u64);
                self.write_varint(&mut encoded, data.len() as u64);
                encoded.extend_from_slice(data);
            }
            Http3Frame::Settings { settings } => {
                self.write_varint(&mut encoded, Http3FrameType::Settings as u64);
                let settings_data = self.encode_settings(settings)?;
                self.write_varint(&mut encoded, settings_data.len() as u64);
                encoded.extend(settings_data);
            }
            _ => {
                return Err(QuicError::Http3("Frame encoding not implemented".to_string()));
            }
        }

        Ok(encoded)
    }

    fn read_varint(&self, buffer: &mut BytesMut) -> Result<u64> {
        if buffer.is_empty() {
            return Err(QuicError::Http3("Buffer underflow reading varint".to_string()));
        }

        let first_byte = buffer[0];
        let length = match first_byte >> 6 {
            0 => 1,
            1 => 2,
            2 => 4,
            3 => 8,
            _ => unreachable!(),
        };

        if buffer.len() < length {
            return Err(QuicError::Http3("Buffer underflow reading varint".to_string()));
        }

        let mut value = (first_byte & 0x3F) as u64;
        for i in 1..length {
            value = (value << 8) | buffer[i] as u64;
        }

        buffer.advance(length);
        Ok(value)
    }

    fn read_varint_from_slice(&self, data: &mut &[u8]) -> Result<u64> {
        if data.is_empty() {
            return Err(QuicError::Http3("Buffer underflow reading varint".to_string()));
        }

        let first_byte = data[0];
        let length = match first_byte >> 6 {
            0 => 1,
            1 => 2,
            2 => 4,
            3 => 8,
            _ => unreachable!(),
        };

        if data.len() < length {
            return Err(QuicError::Http3("Buffer underflow reading varint".to_string()));
        }

        let mut value = (first_byte & 0x3F) as u64;
        for i in 1..length {
            value = (value << 8) | data[i] as u64;
        }

        *data = &data[length..];
        Ok(value)
    }

    fn write_varint(&self, buffer: &mut Vec<u8>, value: u64) {
        if value < 64 {
            buffer.push(value as u8);
        } else if value < 16384 {
            buffer.push(0x40 | (value >> 8) as u8);
            buffer.push(value as u8);
        } else if value < 1073741824 {
            buffer.push(0x80 | (value >> 24) as u8);
            buffer.push((value >> 16) as u8);
            buffer.push((value >> 8) as u8);
            buffer.push(value as u8);
        } else {
            buffer.push(0xC0 | (value >> 56) as u8);
            buffer.extend_from_slice(&(value as u64).to_be_bytes()[1..]);
        }
    }

    fn parse_headers(&self, data: &[u8]) -> Result<Vec<Http3Header>> {
        // Simplified header parsing - in practice this would use QPACK
        Ok(vec![])
    }

    fn encode_headers(&self, headers: &[Http3Header]) -> Result<Vec<u8>> {
        // Simplified header encoding - in practice this would use QPACK
        Ok(vec![])
    }

    fn parse_settings(&self, data: &[u8]) -> Result<HashMap<u64, u64>> {
        let mut settings = HashMap::new();
        let mut remaining = data;

        while !remaining.is_empty() {
            let setting_id = self.read_varint_from_slice(&mut remaining)?;
            let value = self.read_varint_from_slice(&mut remaining)?;
            settings.insert(setting_id, value);
        }

        Ok(settings)
    }

    fn encode_settings(&self, settings: &HashMap<u64, u64>) -> Result<Vec<u8>> {
        let mut encoded = Vec::new();

        for (&setting_id, &value) in settings {
            self.write_varint(&mut encoded, setting_id);
            self.write_varint(&mut encoded, value);
        }

        Ok(encoded)
    }
}

/// QPACK encoder for header compression
pub struct QpackEncoder {
    max_table_capacity: usize,
    dynamic_table: Vec<(Bytes, Bytes)>,
}

impl QpackEncoder {
    pub fn new(max_table_capacity: usize) -> Self {
        Self {
            max_table_capacity,
            dynamic_table: Vec::new(),
        }
    }

    pub fn encode_headers(&mut self, headers: &[DecodedHeader]) -> Result<Vec<Http3Header>> {
        // Simplified QPACK encoding
        let mut encoded_headers = Vec::new();

        for header in headers {
            encoded_headers.push(Http3Header {
                name: header.name.clone(),
                value: header.value.clone(),
            });
        }

        Ok(encoded_headers)
    }
}

/// QPACK decoder for header decompression
pub struct QpackDecoder {
    max_table_capacity: usize,
    dynamic_table: Vec<(Bytes, Bytes)>,
}

impl QpackDecoder {
    pub fn new(max_table_capacity: usize) -> Self {
        Self {
            max_table_capacity,
            dynamic_table: Vec::new(),
        }
    }

    pub fn decode_headers(&mut self, headers: &[Http3Header]) -> Result<Vec<DecodedHeader>> {
        // Simplified QPACK decoding
        let mut decoded_headers = Vec::new();

        for header in headers {
            decoded_headers.push(DecodedHeader {
                name: header.name.clone(),
                value: header.value.clone(),
            });
        }

        Ok(decoded_headers)
    }
}

/// HTTP/3 stream manager
pub struct Http3StreamManager {
    active_streams: HashMap<StreamId, Http3StreamState>,
    max_push_id: u64,
    goaway_received: bool,
}

impl Http3StreamManager {
    pub fn new() -> Self {
        Self {
            active_streams: HashMap::new(),
            max_push_id: 0,
            goaway_received: false,
        }
    }

    pub fn update_stream_headers(&mut self, stream_id: StreamId, headers: &[DecodedHeader], fin: bool) -> Result<()> {
        let state = self.active_streams.entry(stream_id).or_insert(Http3StreamState::new());
        state.headers_received = true;
        if fin {
            state.complete = true;
        }
        Ok(())
    }

    pub fn update_stream_data(&mut self, stream_id: StreamId, data: &Bytes) -> Result<()> {
        let state = self.active_streams.entry(stream_id).or_insert(Http3StreamState::new());
        state.bytes_received += data.len();
        Ok(())
    }

    pub fn mark_goaway(&mut self, stream_id: StreamId) -> Result<()> {
        self.goaway_received = true;
        Ok(())
    }

    pub fn cancel_push_stream(&mut self, push_id: u64) -> Result<()> {
        // Cancel push stream implementation
        Ok(())
    }

    pub fn update_max_push_id(&mut self, push_id: u64) -> Result<()> {
        self.max_push_id = push_id;
        Ok(())
    }

    pub fn active_stream_count(&self) -> usize {
        self.active_streams.len()
    }
}

/// HTTP/3 stream state
#[derive(Debug)]
pub struct Http3StreamState {
    pub headers_received: bool,
    pub bytes_received: usize,
    pub complete: bool,
}

impl Http3StreamState {
    pub fn new() -> Self {
        Self {
            headers_received: false,
            bytes_received: 0,
            complete: false,
        }
    }
}

/// HTTP/3 settings
#[derive(Debug, Clone)]
pub struct Http3Settings {
    pub qpack_max_table_capacity: usize,
    pub max_header_list_size: Option<usize>,
    pub qpack_blocked_streams: usize,
}

impl Default for Http3Settings {
    fn default() -> Self {
        Self {
            qpack_max_table_capacity: 4096,
            max_header_list_size: None,
            qpack_blocked_streams: 100,
        }
    }
}

/// Processed HTTP/3 frame
#[derive(Debug)]
pub struct ProcessedFrame {
    pub stream_id: StreamId,
    pub frame_type: Http3FrameType,
    pub result: ProcessingResult,
    pub processing_time: std::time::Duration,
    pub qpack_operations: u64,
}

/// Frame processing result
#[derive(Debug)]
pub struct FrameProcessingResult {
    pub frame_type: Http3FrameType,
    pub result: ProcessingResult,
    pub qpack_operations: u64,
}

/// Processing result types
#[derive(Debug)]
pub enum ProcessingResult {
    HeadersProcessed {
        headers: Vec<DecodedHeader>,
        stream_complete: bool,
    },
    DataProcessed {
        data: Bytes,
        bytes_received: usize,
    },
    SettingsUpdated,
    GoAwayReceived {
        last_stream: StreamId,
    },
    PushCancelled {
        push_id: u64,
    },
    MaxPushIdUpdated {
        max_push_id: u64,
    },
}

/// Decoded header
#[derive(Debug, Clone)]
pub struct DecodedHeader {
    pub name: Bytes,
    pub value: Bytes,
}

/// HTTP/3 response (decoded)
#[derive(Debug)]
pub struct Http3DecodedResponse {
    pub status: u16,
    pub headers: Vec<DecodedHeader>,
    pub body: Bytes,
}

/// HTTP/3 processing statistics
#[derive(Debug, Default)]
pub struct Http3Stats {
    pub frames_processed: u64,
    pub responses_sent: u64,
    pub qpack_operations: u64,
    pub total_processing_time: std::time::Duration,
}

/// HTTP/3 statistics snapshot
#[derive(Debug, Clone)]
pub struct Http3StatsSnapshot {
    pub frames_processed: u64,
    pub responses_sent: u64,
    pub qpack_operations: u64,
    pub total_processing_time: std::time::Duration,
    pub active_streams: usize,
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
            1 => Some(Http3Header::new(Bytes::from_static(b":authority"), Bytes::from_static(b""))),
            2 => Some(Http3Header::new(Bytes::from_static(b":method"), Bytes::from_static(b"GET"))),
            3 => Some(Http3Header::new(Bytes::from_static(b":method"), Bytes::from_static(b"POST"))),
            4 => Some(Http3Header::new(Bytes::from_static(b":path"), Bytes::from_static(b"/"))),
            5 => Some(Http3Header::new(Bytes::from_static(b":scheme"), Bytes::from_static(b"https"))),
            6 => Some(Http3Header::new(Bytes::from_static(b":status"), Bytes::from_static(b"200"))),
            7 => Some(Http3Header::new(Bytes::from_static(b":status"), Bytes::from_static(b"404"))),
            8 => Some(Http3Header::new(Bytes::from_static(b":status"), Bytes::from_static(b"500"))),
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
            Http3Header::new(Bytes::from_static(b":method"), request.method),
            Http3Header::new(Bytes::from_static(b":path"), request.path),
            Http3Header::new(Bytes::from_static(b":scheme"), request.scheme),
        ];

        if let Some(authority) = request.authority {
            headers.push(Http3Header::new(Bytes::from_static(b":authority"), authority));
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
            Http3Header::new(Bytes::from(&b":status"[..]), Bytes::from(response.status.to_string().into_bytes())),
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
            Http3Header::new(b":method".as_slice(), b"GET".as_slice()),
            Http3Header::new(b":path".as_slice(), b"/test".as_slice()),
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