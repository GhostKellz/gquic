//! QPACK dynamic table implementation

use std::collections::VecDeque;
use indexmap::IndexMap;
use crate::http3::error::Http3Error;

/// Entry in the QPACK dynamic table
#[derive(Debug, Clone)]
pub struct QpackTableEntry {
    pub name: String,
    pub value: String,
    pub size: usize,
}

impl QpackTableEntry {
    pub fn new(name: String, value: String) -> Self {
        let size = name.len() + value.len() + 32; // RFC 7541 overhead
        Self { name, value, size }
    }
}

/// QPACK dynamic table for header compression
#[derive(Debug)]
pub struct QpackTable {
    /// Table entries stored in insertion order
    entries: VecDeque<QpackTableEntry>,
    /// Index mapping for fast lookups
    index_map: IndexMap<String, usize>,
    /// Current table size in bytes
    current_size: usize,
    /// Maximum table capacity
    max_capacity: usize,
    /// Insert count (for QPACK stream instructions)
    insert_count: u64,
}

impl QpackTable {
    pub fn new(max_capacity: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            index_map: IndexMap::new(),
            current_size: 0,
            max_capacity,
            insert_count: 0,
        }
    }

    /// Insert a new entry into the dynamic table
    pub fn insert(&mut self, name: String, value: String) -> Result<u64, Http3Error> {
        let entry = QpackTableEntry::new(name.clone(), value.clone());
        
        // Check if entry fits in table
        if entry.size > self.max_capacity {
            return Err(Http3Error::ProtocolError("Entry too large for table".into()));
        }

        // Evict entries to make room
        while self.current_size + entry.size > self.max_capacity && !self.entries.is_empty() {
            self.evict_oldest();
        }

        // Insert new entry
        let key = format!("{}:{}", name, value);
        let index = self.entries.len();
        
        self.entries.push_back(entry.clone());
        self.index_map.insert(key, index);
        self.current_size += entry.size;
        self.insert_count += 1;

        Ok(self.insert_count)
    }

    /// Get entry by absolute index
    pub fn get(&self, index: usize) -> Option<&QpackTableEntry> {
        self.entries.get(index)
    }

    /// Get entry by relative index (from most recent)
    pub fn get_relative(&self, relative_index: usize) -> Option<&QpackTableEntry> {
        if relative_index >= self.entries.len() {
            return None;
        }
        let index = self.entries.len() - 1 - relative_index;
        self.entries.get(index)
    }

    /// Find entry index by name and value
    pub fn find(&self, name: &str, value: &str) -> Option<usize> {
        let key = format!("{}:{}", name, value);
        self.index_map.get(&key).copied()
    }

    /// Find entry index by name only (for name-only matches)
    pub fn find_name(&self, name: &str) -> Option<usize> {
        for (index, entry) in self.entries.iter().enumerate() {
            if entry.name == name {
                return Some(index);
            }
        }
        None
    }

    /// Get the current insert count
    pub fn insert_count(&self) -> u64 {
        self.insert_count
    }

    /// Get current table size
    pub fn size(&self) -> usize {
        self.current_size
    }

    /// Get maximum capacity
    pub fn capacity(&self) -> usize {
        self.max_capacity
    }

    /// Set maximum capacity and evict entries if necessary
    pub fn set_capacity(&mut self, new_capacity: usize) {
        self.max_capacity = new_capacity;
        
        while self.current_size > self.max_capacity && !self.entries.is_empty() {
            self.evict_oldest();
        }
    }

    /// Number of entries in the table
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if table is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all entries from the table
    pub fn clear(&mut self) {
        self.entries.clear();
        self.index_map.clear();
        self.current_size = 0;
    }

    /// Evict the oldest entry from the table
    fn evict_oldest(&mut self) {
        if let Some(entry) = self.entries.pop_front() {
            let key = format!("{}:{}", entry.name, entry.value);
            self.index_map.shift_remove(&key);
            self.current_size -= entry.size;
            
            // Update indices in the map
            for (_, index) in self.index_map.iter_mut() {
                if *index > 0 {
                    *index -= 1;
                }
            }
        }
    }

    /// Get all entries as a vector (for debugging)
    pub fn entries(&self) -> Vec<&QpackTableEntry> {
        self.entries.iter().collect()
    }
}
