//! QPACK encoder implementation

use std::collections::HashMap;
use bytes::{Bytes, BytesMut, BufMut};
use indexmap::IndexMap;
use crate::http3::error::Http3Error;

/// QPACK field line representation
#[derive(Debug, Clone)]
pub struct FieldLine {
    pub name: Bytes,
    pub value: Bytes,
}

/// QPACK encoder for header compression
#[derive(Debug)]
pub struct QpackEncoder {
    /// Dynamic table for frequently used header fields
    dynamic_table: IndexMap<String, String>,
    /// Maximum table capacity
    max_table_capacity: usize,
    /// Current table size
    current_table_size: usize,
}

impl QpackEncoder {
    pub fn new(max_table_capacity: usize) -> Self {
        Self {
            dynamic_table: IndexMap::new(),
            max_table_capacity,
            current_table_size: 0,
        }
    }

    /// Encode headers using QPACK compression
    pub fn encode(&mut self, headers: &[(String, String)]) -> Result<Bytes, Http3Error> {
        let mut buf = BytesMut::new();
        
        for (name, value) in headers {
            self.encode_field_line(&mut buf, name, value)?;
        }
        
        Ok(buf.freeze())
    }

    fn encode_field_line(&mut self, buf: &mut BytesMut, name: &str, value: &str) -> Result<(), Http3Error> {
        // Check if header is in static table (simplified)
        if let Some(index) = self.get_static_index(name, value) {
            // Indexed header field
            self.encode_varint(buf, index, 0x80);
        } else if let Some(index) = self.get_dynamic_index(name, value) {
            // Dynamic table indexed field
            self.encode_varint(buf, index + 62, 0x80); // Static table has 61 entries
        } else {
            // Literal header field with incremental indexing
            buf.put_u8(0x40); // Pattern: 01
            self.encode_string(buf, name)?;
            self.encode_string(buf, value)?;
            
            // Add to dynamic table
            self.insert_dynamic_entry(name.to_string(), value.to_string());
        }
        
        Ok(())
    }

    fn encode_varint(&self, buf: &mut BytesMut, mut value: u64, prefix_mask: u8) {
        let prefix_max = (1 << (8 - prefix_mask.leading_zeros())) - 1;
        
        if value < prefix_max as u64 {
            buf.put_u8(prefix_mask | (value as u8));
        } else {
            buf.put_u8(prefix_mask | (prefix_max as u8));
            value -= prefix_max as u64;
            
            while value >= 128 {
                buf.put_u8(((value % 128) + 128) as u8);
                value /= 128;
            }
            buf.put_u8(value as u8);
        }
    }

    fn encode_string(&self, buf: &mut BytesMut, s: &str) -> Result<(), Http3Error> {
        let bytes = s.as_bytes();
        self.encode_varint(buf, bytes.len() as u64, 0x00);
        buf.put_slice(bytes);
        Ok(())
    }

    fn get_static_index(&self, name: &str, value: &str) -> Option<u64> {
        // Simplified static table lookup - in real implementation this would be comprehensive
        match (name, value) {
            (":method", "GET") => Some(17),
            (":method", "POST") => Some(20),
            (":status", "200") => Some(25),
            (":status", "404") => Some(13),
            ("content-type", "application/json") => Some(31),
            _ => None,
        }
    }

    fn get_dynamic_index(&self, name: &str, value: &str) -> Option<u64> {
        self.dynamic_table.get_full(&format!("{}:{}", name, value))
            .map(|(index, _, _)| index as u64)
    }

    fn insert_dynamic_entry(&mut self, name: String, value: String) {
        let entry_size = name.len() + value.len() + 32; // RFC estimate
        
        // Evict entries if necessary
        while self.current_table_size + entry_size > self.max_table_capacity && !self.dynamic_table.is_empty() {
            if let Some((key, _)) = self.dynamic_table.pop_first() {
                self.current_table_size -= key.len() + 32;
            }
        }
        
        if entry_size <= self.max_table_capacity {
            let key = format!("{}:{}", name, value);
            self.dynamic_table.insert(key, format!("{}:{}", name, value));
            self.current_table_size += entry_size;
        }
    }
}