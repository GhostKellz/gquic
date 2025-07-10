//! QPACK decoder implementation

use std::collections::HashMap;
use bytes::Bytes;
use indexmap::IndexMap;
use crate::http3::error::Http3Error;

/// QPACK decoder for header decompression
#[derive(Debug)]
pub struct QpackDecoder {
    /// Dynamic table for frequently used header fields
    dynamic_table: IndexMap<String, String>,
    /// Maximum table capacity
    max_table_capacity: usize,
    /// Current table size
    current_table_size: usize,
}

impl QpackDecoder {
    pub fn new(max_table_capacity: usize) -> Self {
        Self {
            dynamic_table: IndexMap::new(),
            max_table_capacity,
            current_table_size: 0,
        }
    }

    /// Decode headers from QPACK compressed data
    pub fn decode(&mut self, data: &[u8]) -> Result<Vec<(String, String)>, Http3Error> {
        let mut headers = Vec::new();
        let mut cursor = 0;

        while cursor < data.len() {
            let (header, consumed) = self.decode_field_line(&data[cursor..])?;
            headers.push(header);
            cursor += consumed;
        }

        Ok(headers)
    }

    fn decode_field_line(&mut self, data: &[u8]) -> Result<((String, String), usize), Http3Error> {
        if data.is_empty() {
            return Err(Http3Error::ProtocolError("Empty field line data".into()));
        }

        let first_byte = data[0];
        let mut cursor = 0;

        if first_byte & 0x80 != 0 {
            // Indexed Header Field
            let (index, consumed) = self.decode_varint(data, 0x80)?;
            cursor += consumed;
            
            let header = if index < 62 {
                // Static table
                self.get_static_header(index)?
            } else {
                // Dynamic table
                self.get_dynamic_header(index - 62)?
            };
            
            Ok((header, cursor))
        } else if first_byte & 0x40 != 0 {
            // Literal Header Field with Incremental Indexing
            cursor += 1; // Skip the pattern byte
            
            let (name, name_consumed) = self.decode_string(&data[cursor..])?;
            cursor += name_consumed;
            
            let (value, value_consumed) = self.decode_string(&data[cursor..])?;
            cursor += value_consumed;
            
            let header = (name.clone(), value.clone());
            self.insert_dynamic_entry(name, value);
            
            Ok((header, cursor))
        } else {
            // Literal Header Field without Indexing
            cursor += 1; // Skip the pattern byte
            
            let (name, name_consumed) = self.decode_string(&data[cursor..])?;
            cursor += name_consumed;
            
            let (value, value_consumed) = self.decode_string(&data[cursor..])?;
            cursor += value_consumed;
            
            Ok(((name, value), cursor))
        }
    }

    fn decode_varint(&self, data: &[u8], prefix_mask: u8) -> Result<(u64, usize), Http3Error> {
        if data.is_empty() {
            return Err(Http3Error::ProtocolError("Empty varint data".into()));
        }

        let prefix_bits = 8 - prefix_mask.leading_zeros() as u8;
        let prefix_max = (1 << prefix_bits) - 1;
        
        let mut value = (data[0] & !prefix_mask) as u64;
        let mut cursor = 1;

        if value < prefix_max as u64 {
            return Ok((value, cursor));
        }

        let mut shift = 0;
        loop {
            if cursor >= data.len() {
                return Err(Http3Error::ProtocolError("Incomplete varint".into()));
            }

            let byte = data[cursor];
            cursor += 1;

            value += ((byte & 0x7F) as u64) << shift;
            shift += 7;

            if byte & 0x80 == 0 {
                break;
            }

            if shift >= 64 {
                return Err(Http3Error::ProtocolError("Varint too large".into()));
            }
        }

        Ok((value, cursor))
    }

    fn decode_string(&self, data: &[u8]) -> Result<(String, usize), Http3Error> {
        let (length, length_consumed) = self.decode_varint(data, 0x00)?;
        let mut cursor = length_consumed;

        if cursor + length as usize > data.len() {
            return Err(Http3Error::ProtocolError("Incomplete string data".into()));
        }

        let string_bytes = &data[cursor..cursor + length as usize];
        cursor += length as usize;

        let string = String::from_utf8(string_bytes.to_vec())
            .map_err(|_| Http3Error::ProtocolError("Invalid UTF-8 in string".into()))?;

        Ok((string, cursor))
    }

    fn get_static_header(&self, index: u64) -> Result<(String, String), Http3Error> {
        // Simplified static table - in real implementation this would be comprehensive
        let header = match index {
            17 => (":method".to_string(), "GET".to_string()),
            20 => (":method".to_string(), "POST".to_string()),
            25 => (":status".to_string(), "200".to_string()),
            13 => (":status".to_string(), "404".to_string()),
            31 => ("content-type".to_string(), "application/json".to_string()),
            _ => return Err(Http3Error::ProtocolError(format!("Invalid static table index: {}", index))),
        };
        
        Ok(header)
    }

    fn get_dynamic_header(&self, index: u64) -> Result<(String, String), Http3Error> {
        let entry = self.dynamic_table.get_index(index as usize)
            .ok_or_else(|| Http3Error::ProtocolError(format!("Invalid dynamic table index: {}", index)))?;
        
        let parts: Vec<&str> = entry.1.split(':').collect();
        if parts.len() != 2 {
            return Err(Http3Error::ProtocolError("Invalid dynamic table entry format".into()));
        }
        
        Ok((parts[0].to_string(), parts[1].to_string()))
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
            self.dynamic_table.insert(key.clone(), key);
            self.current_table_size += entry_size;
        }
    }
}
