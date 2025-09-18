//! QPACK Header Compression for HTTP/3
//!
//! QPACK is the header compression mechanism for HTTP/3, designed to avoid
//! head-of-line blocking issues while maintaining high compression ratios.

use crate::{QuicError, QuicResult};
use bytes::{Bytes, BytesMut, Buf, BufMut};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

/// QPACK encoder for compressing headers
pub struct QpackEncoder {
    /// Dynamic table
    dynamic_table: DynamicTable,
    /// Maximum dynamic table capacity
    max_table_capacity: usize,
    /// Blocked streams
    blocked_streams: Arc<Mutex<HashMap<u64, BlockedStream>>>,
    /// Encoder stream buffer
    encoder_stream: BytesMut,
    /// Known received count
    known_received_count: u64,
    /// Configuration
    config: QpackConfig,
}

/// QPACK decoder for decompressing headers
pub struct QpackDecoder {
    /// Dynamic table
    dynamic_table: DynamicTable,
    /// Maximum dynamic table capacity
    max_table_capacity: usize,
    /// Blocked streams
    blocked_streams: Arc<Mutex<HashMap<u64, Vec<u8>>>>,
    /// Decoder stream buffer
    decoder_stream: BytesMut,
    /// Total inserted count
    total_inserted_count: u64,
    /// Configuration
    config: QpackConfig,
}

/// QPACK configuration
#[derive(Debug, Clone)]
pub struct QpackConfig {
    /// Maximum dynamic table size
    pub max_table_size: usize,
    /// Maximum blocked streams
    pub max_blocked_streams: usize,
    /// Enable huffman encoding
    pub huffman_encoding: bool,
    /// Duplicate entry threshold
    pub duplicate_threshold: f64,
}

impl Default for QpackConfig {
    fn default() -> Self {
        Self {
            max_table_size: 4096,
            max_blocked_streams: 100,
            huffman_encoding: true,
            duplicate_threshold: 0.8,
        }
    }
}

/// Dynamic table for QPACK
#[derive(Debug, Clone)]
struct DynamicTable {
    /// Table entries
    entries: VecDeque<TableEntry>,
    /// Current size in bytes
    current_size: usize,
    /// Insertion count
    insertion_count: u64,
    /// Dropping count
    dropping_count: u64,
}

/// Table entry
#[derive(Debug, Clone)]
struct TableEntry {
    /// Header name
    name: Vec<u8>,
    /// Header value
    value: Vec<u8>,
    /// Entry size
    size: usize,
    /// Insertion index
    index: u64,
}

impl TableEntry {
    /// Create a new table entry
    fn new(name: Vec<u8>, value: Vec<u8>, index: u64) -> Self {
        let size = name.len() + value.len() + 32;
        Self { name, value, size, index }
    }
}

/// Blocked stream information
#[derive(Debug)]
struct BlockedStream {
    /// Stream ID
    stream_id: u64,
    /// Required insert count
    required_insert_count: u64,
    /// Encoded headers
    encoded_headers: Vec<u8>,
}

/// Static table for QPACK
const STATIC_TABLE: &[(&[u8], &[u8])] = &[
    (b":authority", b""),
    (b":path", b"/"),
    (b"age", b"0"),
    (b"content-disposition", b""),
    (b"content-length", b"0"),
    (b"cookie", b""),
    (b"date", b""),
    (b"etag", b""),
    (b"if-modified-since", b""),
    (b"if-none-match", b""),
    (b"last-modified", b""),
    (b"link", b""),
    (b"location", b""),
    (b"referer", b""),
    (b"set-cookie", b""),
    (b":method", b"CONNECT"),
    (b":method", b"DELETE"),
    (b":method", b"GET"),
    (b":method", b"HEAD"),
    (b":method", b"OPTIONS"),
    (b":method", b"POST"),
    (b":method", b"PUT"),
    (b":scheme", b"http"),
    (b":scheme", b"https"),
    (b":status", b"103"),
    (b":status", b"200"),
    (b":status", b"304"),
    (b":status", b"404"),
    (b":status", b"503"),
    (b"accept", b"*/*"),
    (b"accept", b"application/dns-message"),
    (b"accept-encoding", b"gzip, deflate, br"),
    (b"accept-ranges", b"bytes"),
    (b"access-control-allow-headers", b"cache-control"),
    (b"access-control-allow-headers", b"content-type"),
    (b"access-control-allow-origin", b"*"),
    (b"cache-control", b"max-age=0"),
    (b"cache-control", b"max-age=2592000"),
    (b"cache-control", b"max-age=604800"),
    (b"cache-control", b"no-cache"),
    (b"cache-control", b"no-store"),
    (b"cache-control", b"public, max-age=31536000"),
    (b"content-encoding", b"br"),
    (b"content-encoding", b"gzip"),
    (b"content-type", b"application/dns-message"),
    (b"content-type", b"application/javascript"),
    (b"content-type", b"application/json"),
    (b"content-type", b"application/x-www-form-urlencoded"),
    (b"content-type", b"image/gif"),
    (b"content-type", b"image/jpeg"),
    (b"content-type", b"image/png"),
    (b"content-type", b"text/css"),
    (b"content-type", b"text/html; charset=utf-8"),
    (b"content-type", b"text/plain"),
    (b"content-type", b"text/plain;charset=utf-8"),
    (b"range", b"bytes=0-"),
    (b"strict-transport-security", b"max-age=31536000"),
    (b"strict-transport-security", b"max-age=31536000; includesubdomains"),
    (b"strict-transport-security", b"max-age=31536000; includesubdomains; preload"),
    (b"vary", b"accept-encoding"),
    (b"vary", b"origin"),
    (b"x-content-type-options", b"nosniff"),
    (b"x-xss-protection", b"1; mode=block"),
    (b":status", b"100"),
    (b":status", b"204"),
    (b":status", b"206"),
    (b":status", b"302"),
    (b":status", b"400"),
    (b":status", b"403"),
    (b":status", b"421"),
    (b":status", b"425"),
    (b":status", b"500"),
    (b"accept-language", b""),
    (b"access-control-allow-credentials", b"FALSE"),
    (b"access-control-allow-credentials", b"TRUE"),
    (b"access-control-allow-headers", b"*"),
    (b"access-control-allow-methods", b"get"),
    (b"access-control-allow-methods", b"get, post, options"),
    (b"access-control-allow-methods", b"options"),
    (b"access-control-expose-headers", b"content-length"),
    (b"access-control-request-headers", b"content-type"),
    (b"access-control-request-method", b"get"),
    (b"access-control-request-method", b"post"),
    (b"alt-svc", b"clear"),
    (b"authorization", b""),
    (b"content-security-policy", b"script-src 'none'; object-src 'none'; base-uri 'none'"),
    (b"early-data", b"1"),
    (b"expect-ct", b""),
    (b"forwarded", b""),
    (b"if-range", b""),
    (b"origin", b""),
    (b"purpose", b"prefetch"),
    (b"server", b""),
    (b"timing-allow-origin", b"*"),
    (b"upgrade-insecure-requests", b"1"),
    (b"user-agent", b""),
    (b"x-forwarded-for", b""),
    (b"x-frame-options", b"deny"),
    (b"x-frame-options", b"sameorigin"),
];

impl DynamicTable {
    /// Create a new dynamic table
    fn new() -> Self {
        Self {
            entries: VecDeque::new(),
            current_size: 0,
            insertion_count: 0,
            dropping_count: 0,
        }
    }

    /// Insert an entry
    fn insert(&mut self, name: Vec<u8>, value: Vec<u8>, max_capacity: usize) {
        let entry = TableEntry::new(name, value, self.insertion_count);
        self.insertion_count += 1;

        // Evict entries if needed
        while self.current_size + entry.size > max_capacity && !self.entries.is_empty() {
            if let Some(evicted) = self.entries.pop_back() {
                self.current_size -= evicted.size;
                self.dropping_count += 1;
            }
        }

        if self.current_size + entry.size <= max_capacity {
            self.current_size += entry.size;
            self.entries.push_front(entry);
        }
    }

    /// Get entry by absolute index
    fn get_absolute(&self, index: u64) -> Option<&TableEntry> {
        if index < self.dropping_count {
            return None;
        }
        let relative = index - self.dropping_count;
        self.entries.get(relative as usize)
    }

    /// Get entry by relative index
    fn get_relative(&self, index: u64) -> Option<&TableEntry> {
        self.entries.get(index as usize)
    }

    /// Find entry by name and value
    fn find(&self, name: &[u8], value: &[u8]) -> Option<u64> {
        self.entries.iter()
            .position(|e| e.name == name && e.value == value)
            .map(|i| self.insertion_count - 1 - i as u64)
    }

    /// Find entry by name only
    fn find_name(&self, name: &[u8]) -> Option<u64> {
        self.entries.iter()
            .position(|e| e.name == name)
            .map(|i| self.insertion_count - 1 - i as u64)
    }
}

impl QpackEncoder {
    /// Create a new QPACK encoder
    pub fn new(config: QpackConfig) -> Self {
        Self {
            dynamic_table: DynamicTable::new(),
            max_table_capacity: config.max_table_size,
            blocked_streams: Arc::new(Mutex::new(HashMap::new())),
            encoder_stream: BytesMut::with_capacity(4096),
            known_received_count: 0,
            config,
        }
    }

    /// Encode headers
    pub async fn encode(
        &mut self,
        headers: &[(Vec<u8>, Vec<u8>)],
        stream_id: u64,
    ) -> QuicResult<Vec<u8>> {
        let mut encoded = BytesMut::new();

        // Encode required insert count
        let required_insert_count = self.dynamic_table.insertion_count;
        self.encode_prefix(&mut encoded, required_insert_count, 0);

        // Encode each header
        for (name, value) in headers {
            self.encode_header(&mut encoded, name, value).await?;
        }

        Ok(encoded.to_vec())
    }

    /// Encode a single header
    async fn encode_header(
        &mut self,
        buf: &mut BytesMut,
        name: &[u8],
        value: &[u8],
    ) -> QuicResult<()> {
        // Try static table
        if let Some(static_index) = Self::find_in_static_table(name, value) {
            // Indexed header field
            buf.put_u8(0xC0 | (static_index as u8));
            return Ok(());
        }

        // Try dynamic table
        if let Some(dynamic_index) = self.dynamic_table.find(name, value) {
            // Indexed header field
            let index = dynamic_index + STATIC_TABLE.len() as u64;
            self.encode_integer(buf, 6, 0x80, index);
            return Ok(());
        }

        // Check if name exists
        if let Some(name_index) = self.find_name_index(name) {
            // Literal with name reference
            self.encode_integer(buf, 4, 0x50, name_index);
        } else {
            // Literal with name literal
            buf.put_u8(0x20);
            self.encode_string(buf, name);
        }

        // Encode value
        self.encode_string(buf, value);

        // Maybe insert into dynamic table
        if self.should_index(name, value) {
            self.dynamic_table.insert(
                name.to_vec(),
                value.to_vec(),
                self.max_table_capacity
            );

            // Send insert instruction on encoder stream
            self.encoder_stream.put_u8(0x80);
            self.encode_string(&mut self.encoder_stream, name);
            self.encode_string(&mut self.encoder_stream, value);
        }

        Ok(())
    }

    /// Find in static table
    fn find_in_static_table(name: &[u8], value: &[u8]) -> Option<usize> {
        STATIC_TABLE.iter()
            .position(|(n, v)| n == &name && v == &value)
    }

    /// Find name index
    fn find_name_index(&self, name: &[u8]) -> u64 {
        // Check static table
        if let Some(idx) = STATIC_TABLE.iter().position(|(n, _)| n == &name) {
            return idx as u64;
        }

        // Check dynamic table
        if let Some(idx) = self.dynamic_table.find_name(name) {
            return idx + STATIC_TABLE.len() as u64;
        }

        0
    }

    /// Should index this header
    fn should_index(&self, name: &[u8], value: &[u8]) -> bool {
        // Don't index sensitive headers
        if name == b"cookie" || name == b"set-cookie" || name == b"authorization" {
            return false;
        }

        // Don't index large values
        if value.len() > 100 {
            return false;
        }

        true
    }

    /// Encode prefix
    fn encode_prefix(&self, buf: &mut BytesMut, required_insert: u64, base: u64) {
        // Encode required insert count
        self.encode_integer(buf, 8, 0x00, required_insert);

        // Encode base
        if base > 0 {
            buf.put_u8(0x80);
            self.encode_integer(buf, 7, 0x00, base);
        } else {
            buf.put_u8(0x00);
        }
    }

    /// Encode integer
    fn encode_integer(&self, buf: &mut BytesMut, prefix_bits: u8, pattern: u8, value: u64) {
        let max_prefix = (1 << prefix_bits) - 1;

        if value < max_prefix as u64 {
            buf.put_u8(pattern | value as u8);
        } else {
            buf.put_u8(pattern | max_prefix);
            let mut v = value - max_prefix as u64;

            while v >= 128 {
                buf.put_u8((v & 0x7F) as u8 | 0x80);
                v >>= 7;
            }

            buf.put_u8(v as u8);
        }
    }

    /// Encode string
    fn encode_string(&self, buf: &mut BytesMut, value: &[u8]) {
        if self.config.huffman_encoding {
            // Huffman encoding (simplified)
            buf.put_u8(0x80 | (value.len() as u8));
            buf.put_slice(value);
        } else {
            // Raw string
            self.encode_integer(buf, 7, 0x00, value.len() as u64);
            buf.put_slice(value);
        }
    }

    /// Get encoder stream data
    pub fn encoder_stream_data(&mut self) -> Vec<u8> {
        self.encoder_stream.split().to_vec()
    }

    /// Handle decoder stream data
    pub async fn handle_decoder_stream(&mut self, data: &[u8]) -> QuicResult<()> {
        let mut buf = Bytes::copy_from_slice(data);

        while buf.has_remaining() {
            let first = buf.get_u8();

            if first & 0x80 != 0 {
                // Section acknowledgment
                let stream_id = self.decode_integer(&mut buf, 7)?;
                self.handle_section_ack(stream_id).await?;
            } else if first & 0x40 != 0 {
                // Stream cancellation
                let stream_id = self.decode_integer(&mut buf, 6)?;
                self.handle_stream_cancel(stream_id).await?;
            } else {
                // Insert count increment
                let increment = self.decode_integer(&mut buf, 6)?;
                self.known_received_count += increment;
            }
        }

        Ok(())
    }

    /// Handle section acknowledgment
    async fn handle_section_ack(&mut self, stream_id: u64) -> QuicResult<()> {
        let mut blocked = self.blocked_streams.lock().await;
        blocked.remove(&stream_id);
        Ok(())
    }

    /// Handle stream cancellation
    async fn handle_stream_cancel(&mut self, stream_id: u64) -> QuicResult<()> {
        let mut blocked = self.blocked_streams.lock().await;
        blocked.remove(&stream_id);
        Ok(())
    }

    /// Decode integer
    fn decode_integer(&self, buf: &mut Bytes, prefix_bits: u8) -> QuicResult<u64> {
        let max_prefix = (1 << prefix_bits) - 1;
        let mut value = (buf.get_u8() & max_prefix) as u64;

        if value < max_prefix as u64 {
            return Ok(value);
        }

        let mut shift = 0;
        loop {
            let byte = buf.get_u8();
            value += ((byte & 0x7F) as u64) << shift;
            shift += 7;

            if byte & 0x80 == 0 {
                break;
            }

            if shift > 62 {
                return Err(QuicError::Protocol("Integer too large".into()));
            }
        }

        Ok(value)
    }
}

impl QpackDecoder {
    /// Create a new QPACK decoder
    pub fn new(config: QpackConfig) -> Self {
        Self {
            dynamic_table: DynamicTable::new(),
            max_table_capacity: config.max_table_size,
            blocked_streams: Arc::new(Mutex::new(HashMap::new())),
            decoder_stream: BytesMut::with_capacity(4096),
            total_inserted_count: 0,
            config,
        }
    }

    /// Decode headers
    pub async fn decode(
        &mut self,
        encoded: &[u8],
        stream_id: u64,
    ) -> QuicResult<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut buf = Bytes::copy_from_slice(encoded);
        let mut headers = Vec::new();

        // Decode prefix
        let (required_insert, base) = self.decode_prefix(&mut buf)?;

        // Check if blocked
        if required_insert > self.total_inserted_count {
            let mut blocked = self.blocked_streams.lock().await;
            blocked.insert(stream_id, encoded.to_vec());
            return Err(QuicError::Protocol("Stream blocked".into()));
        }

        // Decode headers
        while buf.has_remaining() {
            let header = self.decode_header(&mut buf)?;
            headers.push(header);
        }

        // Send section acknowledgment
        self.decoder_stream.put_u8(0x80);
        self.encode_integer(&mut self.decoder_stream, 7, 0x00, stream_id);

        Ok(headers)
    }

    /// Decode header field
    fn decode_header(&self, buf: &mut Bytes) -> QuicResult<(Vec<u8>, Vec<u8>)> {
        let first = buf.get_u8();

        if first & 0x80 != 0 {
            // Indexed header field
            let index = self.decode_integer_from_byte(buf, 6, first)?;
            self.get_indexed(index)
        } else if first & 0x40 != 0 {
            // Literal with name reference
            let name_index = self.decode_integer_from_byte(buf, 4, first)?;
            let name = self.get_name(name_index)?;
            let value = self.decode_string(buf)?;
            Ok((name, value))
        } else if first & 0x20 != 0 {
            // Literal with name literal
            let name = self.decode_string(buf)?;
            let value = self.decode_string(buf)?;
            Ok((name, value))
        } else {
            Err(QuicError::Protocol("Invalid header encoding".into()))
        }
    }

    /// Get indexed header
    fn get_indexed(&self, index: u64) -> QuicResult<(Vec<u8>, Vec<u8>)> {
        if index < STATIC_TABLE.len() as u64 {
            let (name, value) = STATIC_TABLE[index as usize];
            Ok((name.to_vec(), value.to_vec()))
        } else {
            let dynamic_index = index - STATIC_TABLE.len() as u64;
            let entry = self.dynamic_table.get_absolute(dynamic_index)
                .ok_or_else(|| QuicError::Protocol("Invalid index".into()))?;
            Ok((entry.name.clone(), entry.value.clone()))
        }
    }

    /// Get name by index
    fn get_name(&self, index: u64) -> QuicResult<Vec<u8>> {
        if index < STATIC_TABLE.len() as u64 {
            Ok(STATIC_TABLE[index as usize].0.to_vec())
        } else {
            let dynamic_index = index - STATIC_TABLE.len() as u64;
            let entry = self.dynamic_table.get_absolute(dynamic_index)
                .ok_or_else(|| QuicError::Protocol("Invalid name index".into()))?;
            Ok(entry.name.clone())
        }
    }

    /// Decode prefix
    fn decode_prefix(&self, buf: &mut Bytes) -> QuicResult<(u64, u64)> {
        let required_insert = self.decode_integer(buf, 8)?;
        let base_byte = buf.get_u8();
        let base = if base_byte & 0x80 != 0 {
            self.decode_integer_from_byte(buf, 7, base_byte)?
        } else {
            0
        };
        Ok((required_insert, base))
    }

    /// Decode integer from byte
    fn decode_integer_from_byte(&self, buf: &mut Bytes, prefix_bits: u8, first: u8) -> QuicResult<u64> {
        let max_prefix = (1 << prefix_bits) - 1;
        let mut value = (first & max_prefix) as u64;

        if value < max_prefix as u64 {
            return Ok(value);
        }

        let mut shift = 0;
        loop {
            let byte = buf.get_u8();
            value += ((byte & 0x7F) as u64) << shift;
            shift += 7;

            if byte & 0x80 == 0 {
                break;
            }

            if shift > 62 {
                return Err(QuicError::Protocol("Integer too large".into()));
            }
        }

        Ok(value)
    }

    /// Decode integer
    fn decode_integer(&self, buf: &mut Bytes, prefix_bits: u8) -> QuicResult<u64> {
        let first = buf.get_u8();
        self.decode_integer_from_byte(buf, prefix_bits, first)
    }

    /// Decode string
    fn decode_string(&self, buf: &mut Bytes) -> QuicResult<Vec<u8>> {
        let first = buf.get_u8();
        let huffman = first & 0x80 != 0;
        let length = self.decode_integer_from_byte(buf, 7, first)? as usize;

        if buf.remaining() < length {
            return Err(QuicError::Protocol("String too long".into()));
        }

        let mut value = vec![0u8; length];
        buf.copy_to_slice(&mut value);

        if huffman {
            // Huffman decoding (simplified - just return as-is)
            Ok(value)
        } else {
            Ok(value)
        }
    }

    /// Encode integer for decoder stream
    fn encode_integer(&self, buf: &mut BytesMut, prefix_bits: u8, pattern: u8, value: u64) {
        let max_prefix = (1 << prefix_bits) - 1;

        if value < max_prefix as u64 {
            buf.put_u8(pattern | value as u8);
        } else {
            buf.put_u8(pattern | max_prefix);
            let mut v = value - max_prefix as u64;

            while v >= 128 {
                buf.put_u8((v & 0x7F) as u8 | 0x80);
                v >>= 7;
            }

            buf.put_u8(v as u8);
        }
    }

    /// Get decoder stream data
    pub fn decoder_stream_data(&mut self) -> Vec<u8> {
        self.decoder_stream.split().to_vec()
    }

    /// Handle encoder stream data
    pub async fn handle_encoder_stream(&mut self, data: &[u8]) -> QuicResult<()> {
        let mut buf = Bytes::copy_from_slice(data);

        while buf.has_remaining() {
            let first = buf.get_u8();

            if first & 0x80 != 0 {
                // Insert with name reference
                let name_index = self.decode_integer_from_byte(&mut buf, 6, first)?;
                let name = self.get_name(name_index)?;
                let value = self.decode_string(&mut buf)?;
                self.dynamic_table.insert(name, value, self.max_table_capacity);
                self.total_inserted_count += 1;
            } else if first & 0x40 != 0 {
                // Insert with name literal
                let name = self.decode_string(&mut buf)?;
                let value = self.decode_string(&mut buf)?;
                self.dynamic_table.insert(name, value, self.max_table_capacity);
                self.total_inserted_count += 1;
            } else if first & 0x20 != 0 {
                // Duplicate
                let index = self.decode_integer_from_byte(&mut buf, 5, first)?;
                let entry = self.dynamic_table.get_absolute(index)
                    .ok_or_else(|| QuicError::Protocol("Invalid duplicate index".into()))?;
                self.dynamic_table.insert(
                    entry.name.clone(),
                    entry.value.clone(),
                    self.max_table_capacity
                );
                self.total_inserted_count += 1;
            } else {
                // Set dynamic table capacity
                let capacity = self.decode_integer_from_byte(&mut buf, 5, first)? as usize;
                self.max_table_capacity = capacity;
            }
        }

        // Unblock streams if possible
        self.unblock_streams().await?;

        Ok(())
    }

    /// Unblock streams that are now decodeable
    async fn unblock_streams(&mut self) -> QuicResult<()> {
        let mut blocked = self.blocked_streams.lock().await;
        let mut unblocked = Vec::new();

        for (stream_id, _) in blocked.iter() {
            unblocked.push(*stream_id);
        }

        for stream_id in unblocked {
            blocked.remove(&stream_id);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_static_table_lookup() {
        let name = b":method";
        let value = b"GET";
        let index = QpackEncoder::find_in_static_table(name, value);
        assert!(index.is_some());
    }

    #[tokio::test]
    async fn test_encode_decode() {
        let config = QpackConfig::default();
        let mut encoder = QpackEncoder::new(config.clone());
        let mut decoder = QpackDecoder::new(config);

        let headers = vec![
            (b":method".to_vec(), b"GET".to_vec()),
            (b":path".to_vec(), b"/".to_vec()),
            (b":scheme".to_vec(), b"https".to_vec()),
        ];

        let encoded = encoder.encode(&headers, 1).await.unwrap();
        let decoded = decoder.decode(&encoded, 1).await.unwrap();

        assert_eq!(headers, decoded);
    }
}