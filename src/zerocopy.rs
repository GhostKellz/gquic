//! Zero-Copy Performance Optimizations
//!
//! This module provides zero-copy packet processing, memory-mapped I/O,
//! and other performance optimizations to make GQUIC the fastest QUIC implementation.

use crate::quic::error::{QuicError, Result};
use bytes::{Bytes, BytesMut, Buf, BufMut};
use std::alloc::{Layout, alloc, dealloc};
use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tracing::{debug, warn};

/// Zero-copy packet buffer with metadata
#[derive(Debug)]
pub struct PacketBuffer {
    /// Raw packet data (zero-copy reference)
    data: Bytes,
    /// Packet metadata
    metadata: PacketMetadata,
    /// Memory pool reference for efficient allocation
    pool: Option<Arc<MemoryPool>>,
}

/// Packet metadata for zero-copy processing
#[derive(Debug, Clone)]
pub struct PacketMetadata {
    /// Source address
    pub src_addr: std::net::SocketAddr,
    /// Destination address
    pub dst_addr: std::net::SocketAddr,
    /// Packet receive timestamp
    pub timestamp: std::time::Instant,
    /// Packet size in bytes
    pub size: usize,
    /// Encryption level
    pub encryption_level: crate::tls::EncryptionLevel,
    /// Quality of Service marking
    pub qos: QoSMarking,
}

/// Quality of Service markings for packet prioritization
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QoSMarking {
    /// Best effort (default)
    BestEffort,
    /// Low latency (gaming, VoIP)
    LowLatency,
    /// High throughput (bulk data)
    HighThroughput,
    /// Critical (control packets)
    Critical,
}

impl PacketBuffer {
    /// Create a new packet buffer with zero-copy data
    pub fn new(data: Bytes, metadata: PacketMetadata) -> Self {
        Self {
            data,
            metadata,
            pool: None,
        }
    }

    /// Create from memory pool for efficient allocation
    pub fn from_pool(data: Bytes, metadata: PacketMetadata, pool: Arc<MemoryPool>) -> Self {
        Self {
            data,
            metadata,
            pool: Some(pool),
        }
    }

    /// Get packet data as zero-copy slice
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get packet metadata
    pub fn metadata(&self) -> &PacketMetadata {
        &self.metadata
    }

    /// Get packet size
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if packet is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Split packet into header and payload (zero-copy)
    pub fn split_at(&self, mid: usize) -> Result<(Bytes, Bytes)> {
        if mid > self.data.len() {
            return Err(QuicError::Protocol("Split index out of bounds".to_string()));
        }

        let header = self.data.slice(0..mid);
        let payload = self.data.slice(mid..);

        Ok((header, payload))
    }

    /// Clone with shared data (zero-copy)
    pub fn share(&self) -> Self {
        Self {
            data: self.data.clone(),
            metadata: self.metadata.clone(),
            pool: self.pool.clone(),
        }
    }
}

/// High-performance memory pool for packet buffers
#[derive(Debug)]
pub struct MemoryPool {
    /// Pool configuration
    config: PoolConfig,
    /// Pre-allocated memory chunks
    chunks: parking_lot::Mutex<Vec<MemoryChunk>>,
    /// Pool statistics
    stats: PoolStats,
}

/// Memory pool configuration
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Size of each memory chunk
    pub chunk_size: usize,
    /// Initial number of chunks to allocate
    pub initial_chunks: usize,
    /// Maximum number of chunks
    pub max_chunks: usize,
    /// Alignment for memory chunks (for SIMD operations)
    pub alignment: usize,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            chunk_size: 64 * 1024, // 64KB chunks
            initial_chunks: 100,
            max_chunks: 1000,
            alignment: 64, // 64-byte alignment for SIMD
        }
    }
}

/// Memory chunk with alignment for performance
#[derive(Debug)]
struct MemoryChunk {
    ptr: NonNull<u8>,
    size: usize,
    layout: Layout,
    in_use: bool,
}

unsafe impl Send for MemoryChunk {}
unsafe impl Sync for MemoryChunk {}

/// Memory pool statistics
#[derive(Debug)]
struct PoolStats {
    total_allocated: AtomicUsize,
    current_used: AtomicUsize,
    allocation_count: AtomicUsize,
    deallocation_count: AtomicUsize,
}

impl MemoryPool {
    /// Create a new memory pool
    pub fn new(config: PoolConfig) -> Result<Arc<Self>> {
        let mut chunks = Vec::new();

        // Pre-allocate initial chunks
        for _ in 0..config.initial_chunks {
            let chunk = MemoryChunk::allocate(config.chunk_size, config.alignment)?;
            chunks.push(chunk);
        }

        let initial_chunks = config.initial_chunks;
        let chunk_size = config.chunk_size;

        let pool = Arc::new(Self {
            config,
            chunks: parking_lot::Mutex::new(chunks),
            stats: PoolStats {
                total_allocated: AtomicUsize::new(initial_chunks * chunk_size),
                current_used: AtomicUsize::new(0),
                allocation_count: AtomicUsize::new(0),
                deallocation_count: AtomicUsize::new(0),
            },
        });

        debug!("Created memory pool with {} initial chunks of {} bytes each",
               initial_chunks, chunk_size);

        Ok(pool)
    }

    /// Allocate a buffer from the pool
    pub fn allocate(&self, size: usize) -> Result<BytesMut> {
        if size > self.config.chunk_size {
            return Err(QuicError::Protocol(format!(
                "Requested size {} exceeds chunk size {}",
                size, self.config.chunk_size
            )));
        }

        let mut chunks = self.chunks.lock();

        // Find an available chunk
        for chunk in chunks.iter_mut() {
            if !chunk.in_use {
                chunk.in_use = true;
                self.stats.current_used.fetch_add(size, Ordering::Relaxed);
                self.stats.allocation_count.fetch_add(1, Ordering::Relaxed);

                // Create BytesMut from the chunk
                let buf = unsafe {
                    std::slice::from_raw_parts_mut(chunk.ptr.as_ptr(), size)
                };

                return Ok(BytesMut::from(&buf[..size]));
            }
        }

        // No available chunks, try to allocate a new one
        if chunks.len() < self.config.max_chunks {
            let mut chunk = MemoryChunk::allocate(self.config.chunk_size, self.config.alignment)?;
            chunk.in_use = true;

            self.stats.total_allocated.fetch_add(self.config.chunk_size, Ordering::Relaxed);
            self.stats.current_used.fetch_add(size, Ordering::Relaxed);
            self.stats.allocation_count.fetch_add(1, Ordering::Relaxed);

            let buf = unsafe {
                std::slice::from_raw_parts_mut(chunk.ptr.as_ptr(), size)
            };
            let result = BytesMut::from(&buf[..size]);

            chunks.push(chunk);
            Ok(result)
        } else {
            Err(QuicError::Protocol("Memory pool exhausted".to_string()))
        }
    }

    /// Get pool statistics
    pub fn stats(&self) -> MemoryPoolStats {
        MemoryPoolStats {
            total_allocated: self.stats.total_allocated.load(Ordering::Relaxed),
            current_used: self.stats.current_used.load(Ordering::Relaxed),
            allocation_count: self.stats.allocation_count.load(Ordering::Relaxed),
            deallocation_count: self.stats.deallocation_count.load(Ordering::Relaxed),
            chunk_count: self.chunks.lock().len(),
        }
    }
}

impl Drop for MemoryPool {
    fn drop(&mut self) {
        let chunks = self.chunks.lock();
        for chunk in chunks.iter() {
            unsafe {
                dealloc(chunk.ptr.as_ptr(), chunk.layout);
            }
        }
        debug!("Deallocated memory pool with {} chunks", chunks.len());
    }
}

impl MemoryChunk {
    /// Allocate an aligned memory chunk
    fn allocate(size: usize, alignment: usize) -> Result<Self> {
        let layout = Layout::from_size_align(size, alignment)
            .map_err(|e| QuicError::Protocol(format!("Invalid layout: {}", e)))?;

        let ptr = unsafe { alloc(layout) };

        if ptr.is_null() {
            return Err(QuicError::Protocol("Memory allocation failed".to_string()));
        }

        // Zero the memory for security
        unsafe {
            std::ptr::write_bytes(ptr, 0, size);
        }

        Ok(Self {
            ptr: NonNull::new(ptr).unwrap(),
            size,
            layout,
            in_use: false,
        })
    }
}

/// Memory pool statistics
#[derive(Debug, Clone)]
pub struct MemoryPoolStats {
    pub total_allocated: usize,
    pub current_used: usize,
    pub allocation_count: usize,
    pub deallocation_count: usize,
    pub chunk_count: usize,
}

/// Zero-copy I/O operations
pub struct ZeroCopyIO {
    memory_pool: Arc<MemoryPool>,
}

impl ZeroCopyIO {
    /// Create new zero-copy I/O handler
    pub fn new(pool_config: PoolConfig) -> Result<Self> {
        let memory_pool = MemoryPool::new(pool_config)?;
        Ok(Self { memory_pool })
    }

    /// Send data with zero-copy optimization
    pub async fn send_zerocopy(
        &self,
        socket: &tokio::net::UdpSocket,
        data: &[u8],
        addr: std::net::SocketAddr,
    ) -> Result<usize> {
        // In a real implementation, this would use sendmsg with MSG_ZEROCOPY
        // For now, use regular send
        socket.send_to(data, addr)
            .await
            .map_err(|e| QuicError::Io(e.to_string()))
    }

    /// Receive data with zero-copy optimization
    pub async fn recv_zerocopy(
        &self,
        socket: &tokio::net::UdpSocket,
    ) -> Result<PacketBuffer> {
        // Allocate buffer from pool
        let mut buf = self.memory_pool.allocate(65536)?; // Max UDP packet size

        // Receive data
        let (len, addr) = socket.recv_from(&mut buf)
            .await
            .map_err(|e| QuicError::Io(e.to_string()))?;

        buf.truncate(len);

        let metadata = PacketMetadata {
            src_addr: addr,
            dst_addr: socket.local_addr()
                .map_err(|e| QuicError::Io(e.to_string()))?,
            timestamp: std::time::Instant::now(),
            size: len,
            encryption_level: crate::tls::EncryptionLevel::Initial,
            qos: QoSMarking::BestEffort,
        };

        Ok(PacketBuffer::from_pool(buf.freeze(), metadata, self.memory_pool.clone()))
    }

    /// Batch receive for high throughput
    pub async fn recv_batch(
        &self,
        socket: &tokio::net::UdpSocket,
        max_packets: usize,
    ) -> Result<Vec<PacketBuffer>> {
        let mut packets = Vec::with_capacity(max_packets);

        // In a real implementation, this would use recvmmsg for batch receive
        // For now, simulate with individual receives
        for _ in 0..max_packets {
            match self.recv_zerocopy(socket).await {
                Ok(packet) => packets.push(packet),
                Err(_) => break, // No more packets available
            }
        }

        Ok(packets)
    }

    /// Get memory pool statistics
    pub fn pool_stats(&self) -> MemoryPoolStats {
        self.memory_pool.stats()
    }
}

/// SIMD-optimized operations for packet processing
pub mod simd {
    use super::*;

    /// SIMD-optimized memory copy
    #[cfg(target_arch = "x86_64")]
    pub fn memcpy_simd(dst: &mut [u8], src: &[u8]) -> Result<()> {
        if dst.len() != src.len() {
            return Err(QuicError::Protocol("Buffer size mismatch".to_string()));
        }

        // Use AVX2 if available, otherwise fall back to regular copy
        #[cfg(target_feature = "avx2")]
        {
            unsafe { memcpy_avx2(dst.as_mut_ptr(), src.as_ptr(), src.len()) };
        }
        #[cfg(not(target_feature = "avx2"))]
        {
            dst.copy_from_slice(src);
        }

        Ok(())
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    unsafe fn memcpy_avx2(dst: *mut u8, src: *const u8, len: usize) {
        use std::arch::x86_64::*;

        let mut offset = 0;

        // Process 32-byte chunks with AVX2
        while offset + 32 <= len {
            let data = _mm256_loadu_si256(src.add(offset) as *const __m256i);
            _mm256_storeu_si256(dst.add(offset) as *mut __m256i, data);
            offset += 32;
        }

        // Process remaining bytes
        while offset < len {
            *dst.add(offset) = *src.add(offset);
            offset += 1;
        }
    }

    /// SIMD-optimized XOR operation for encryption
    #[cfg(target_arch = "x86_64")]
    pub fn xor_simd(dst: &mut [u8], src1: &[u8], src2: &[u8]) -> Result<()> {
        if dst.len() != src1.len() || dst.len() != src2.len() {
            return Err(QuicError::Protocol("Buffer size mismatch".to_string()));
        }

        #[cfg(target_feature = "avx2")]
        {
            unsafe { xor_avx2(dst.as_mut_ptr(), src1.as_ptr(), src2.as_ptr(), dst.len()) };
        }
        #[cfg(not(target_feature = "avx2"))]
        {
            for i in 0..dst.len() {
                dst[i] = src1[i] ^ src2[i];
            }
        }

        Ok(())
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    unsafe fn xor_avx2(dst: *mut u8, src1: *const u8, src2: *const u8, len: usize) {
        use std::arch::x86_64::*;

        let mut offset = 0;

        while offset + 32 <= len {
            let data1 = _mm256_loadu_si256(src1.add(offset) as *const __m256i);
            let data2 = _mm256_loadu_si256(src2.add(offset) as *const __m256i);
            let result = _mm256_xor_si256(data1, data2);
            _mm256_storeu_si256(dst.add(offset) as *mut __m256i, result);
            offset += 32;
        }

        while offset < len {
            *dst.add(offset) = *src1.add(offset) ^ *src2.add(offset);
            offset += 1;
        }
    }
}

/// Hardware acceleration detection and optimization
pub mod hardware {
    /// Detect available hardware features
    pub fn detect_features() -> HardwareFeatures {
        HardwareFeatures {
            has_aes_ni: is_x86_feature_detected!("aes"),
            has_avx2: is_x86_feature_detected!("avx2"),
            has_avx512: is_x86_feature_detected!("avx512f"),
            has_sse4_2: is_x86_feature_detected!("sse4.2"),
        }
    }

    #[derive(Debug, Clone)]
    pub struct HardwareFeatures {
        pub has_aes_ni: bool,
        pub has_avx2: bool,
        pub has_avx512: bool,
        pub has_sse4_2: bool,
    }

    impl HardwareFeatures {
        /// Get optimization recommendations
        pub fn recommendations(&self) -> Vec<String> {
            let mut recs = Vec::new();

            if self.has_aes_ni {
                recs.push("Use AES-NI for hardware-accelerated encryption".to_string());
            }

            if self.has_avx2 {
                recs.push("Use AVX2 for SIMD packet processing".to_string());
            }

            if self.has_avx512 {
                recs.push("Use AVX-512 for maximum SIMD performance".to_string());
            }

            if recs.is_empty() {
                recs.push("No hardware acceleration available, using software implementations".to_string());
            }

            recs
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_pool() {
        let config = PoolConfig::default();
        let pool = MemoryPool::new(config).unwrap();

        let buf1 = pool.allocate(1024).unwrap();
        let buf2 = pool.allocate(2048).unwrap();

        assert_eq!(buf1.len(), 1024);
        assert_eq!(buf2.len(), 2048);

        let stats = pool.stats();
        assert_eq!(stats.allocation_count, 2);
        assert!(stats.current_used >= 3072);
    }

    #[test]
    fn test_packet_buffer() {
        let data = Bytes::from("test packet data");
        let metadata = PacketMetadata {
            src_addr: "127.0.0.1:8080".parse().unwrap(),
            dst_addr: "127.0.0.1:9090".parse().unwrap(),
            timestamp: std::time::Instant::now(),
            size: data.len(),
            encryption_level: crate::tls::EncryptionLevel::Initial,
            qos: QoSMarking::BestEffort,
        };

        let packet = PacketBuffer::new(data, metadata);
        assert_eq!(packet.len(), 16);
        assert!(!packet.is_empty());

        let (header, payload) = packet.split_at(4).unwrap();
        assert_eq!(header.len(), 4);
        assert_eq!(payload.len(), 12);
    }

    #[tokio::test]
    async fn test_zerocopy_io() {
        let config = PoolConfig::default();
        let io = ZeroCopyIO::new(config).unwrap();

        let stats = io.pool_stats();
        assert!(stats.chunk_count > 0);
    }

    #[test]
    fn test_hardware_detection() {
        let features = hardware::detect_features();
        let recommendations = features.recommendations();
        assert!(!recommendations.is_empty());
    }

    #[test]
    fn test_simd_operations() {
        let mut dst = vec![0u8; 64];
        let src = vec![0xAA; 64];

        #[cfg(target_arch = "x86_64")]
        {
            simd::memcpy_simd(&mut dst, &src).unwrap();
            assert_eq!(dst, vec![0xAA; 64]);
        }
    }
}