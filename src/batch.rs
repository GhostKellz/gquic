//! Batch packet processing for high-throughput QUIC operations
//!
//! This module provides efficient batch processing capabilities for QUIC packets,
//! enabling high-performance networking with reduced syscall overhead and improved
//! throughput through vectorized operations.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use tokio::net::UdpSocket;
use tokio::sync::Notify;
use tracing::{debug, info, warn};

use crate::packet::Packet;
use crate::zerocopy::{PacketBuffer, AdvancedMemoryPool, PoolConfig};
use crate::{QuicResult, QuicError};

/// Configuration for batch processing
#[derive(Debug, Clone)]
pub struct BatchConfig {
    /// Maximum number of packets in a batch
    pub max_batch_size: usize,
    /// Maximum time to wait before processing incomplete batch
    pub batch_timeout: Duration,
    /// Number of worker threads for parallel processing
    pub worker_threads: usize,
    /// Enable vectorized I/O operations
    pub vectorized_io: bool,
    /// Memory pool configuration
    pub memory_pool: PoolConfig,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            max_batch_size: 64,
            batch_timeout: Duration::from_millis(1),
            worker_threads: num_cpus::get(),
            vectorized_io: true,
            memory_pool: PoolConfig::default(),
        }
    }
}

/// Batch packet processor for high-throughput operations
pub struct BatchProcessor {
    config: BatchConfig,
    memory_pool: Arc<AdvancedMemoryPool>,
    input_queue: parking_lot::Mutex<VecDeque<BatchItem>>,
    output_queue: parking_lot::Mutex<VecDeque<ProcessedBatch>>,
    stats: BatchStats,
    batch_ready: Arc<Notify>,
    workers: Vec<tokio::task::JoinHandle<()>>,
}

impl BatchProcessor {
    /// Create a new batch processor
    pub fn new(config: BatchConfig) -> QuicResult<Self> {
        let memory_pool = Arc::new(AdvancedMemoryPool::new(config.memory_pool.clone())
            .map_err(|e| QuicError::Protocol(format!("Failed to create memory pool: {}", e)))?);

        let processor = Self {
            config,
            memory_pool,
            input_queue: parking_lot::Mutex::new(VecDeque::new()),
            output_queue: parking_lot::Mutex::new(VecDeque::new()),
            stats: BatchStats::default(),
            batch_ready: Arc::new(Notify::new()),
            workers: Vec::new(),
        };

        Ok(processor)
    }

    /// Start batch processing workers
    pub fn start_workers(&mut self) -> QuicResult<()> {
        for worker_id in 0..self.config.worker_threads {
            let config = self.config.clone();
            let memory_pool = Arc::clone(&self.memory_pool);
            let input_queue = self.input_queue.clone();
            let output_queue = self.output_queue.clone();
            let batch_ready = Arc::clone(&self.batch_ready);
            let stats = self.stats.clone();

            let worker = tokio::spawn(async move {
                Self::worker_loop(worker_id, config, memory_pool, input_queue, output_queue, batch_ready, stats).await;
            });

            self.workers.push(worker);
        }

        info!("Started {} batch processing workers", self.config.worker_threads);
        Ok(())
    }

    /// Submit packet for batch processing
    pub fn submit_packet(&self, packet: PacketBuffer, addr: SocketAddr, priority: ProcessingPriority) -> QuicResult<()> {
        let item = BatchItem {
            packet,
            addr,
            priority,
            timestamp: Instant::now(),
        };

        {
            let mut queue = self.input_queue.lock();
            queue.push_back(item);

            // Notify workers if batch is ready
            if queue.len() >= self.config.max_batch_size {
                self.batch_ready.notify_waiters();
            }
        }

        self.stats.packets_submitted.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Submit multiple packets for batch processing
    pub fn submit_batch(&self, packets: Vec<(PacketBuffer, SocketAddr, ProcessingPriority)>) -> QuicResult<()> {
        let mut queue = self.input_queue.lock();

        for (packet, addr, priority) in packets {
            let item = BatchItem {
                packet,
                addr,
                priority,
                timestamp: Instant::now(),
            };
            queue.push_back(item);
        }

        // Notify workers if batch is ready
        if queue.len() >= self.config.max_batch_size {
            self.batch_ready.notify_waiters();
        }

        self.stats.packets_submitted.fetch_add(queue.len() as u64, Ordering::Relaxed);
        Ok(())
    }

    /// Retrieve processed batch
    pub fn get_processed_batch(&self) -> Option<ProcessedBatch> {
        self.output_queue.lock().pop_front()
    }

    /// Vectorized receive operation
    pub async fn receive_vectorized(&self, socket: &UdpSocket, max_packets: usize) -> QuicResult<Vec<(PacketBuffer, SocketAddr)>> {
        let mut packets = Vec::with_capacity(max_packets);

        // Use vectorized I/O if supported
        if self.config.vectorized_io {
            #[cfg(target_os = "linux")]
            {
                return self.receive_mmsg(socket, max_packets).await;
            }
        }

        // Fallback to sequential receive
        for _ in 0..max_packets {
            let mut buf = vec![0u8; 65535];
            match tokio::time::timeout(Duration::from_micros(100), socket.recv_from(&mut buf)).await {
                Ok(Ok((len, addr))) => {
                    buf.truncate(len);
                    let packet_data = Bytes::from(buf);

                    let metadata = crate::zerocopy::PacketMetadata {
                        src_addr: addr,
                        dst_addr: socket.local_addr().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
                        timestamp: Instant::now(),
                        size: len,
                        qos: crate::zerocopy::QoSMarking::BestEffort,
                        needs_processing: true,
                        packet_type: crate::zerocopy::PacketTypeHint::Data,
                    };

                    let packet = PacketBuffer::new(packet_data, metadata);
                    packets.push((packet, addr));
                }
                _ => break, // No more packets available
            }
        }

        Ok(packets)
    }

    /// Linux-specific vectorized receive using recvmmsg
    #[cfg(target_os = "linux")]
    async fn receive_mmsg(&self, socket: &UdpSocket, max_packets: usize) -> QuicResult<Vec<(PacketBuffer, SocketAddr)>> {
        use std::mem::MaybeUninit;
        use std::os::unix::io::AsRawFd;

        let mut packets = Vec::with_capacity(max_packets);
        let mut buffers: Vec<Vec<u8>> = (0..max_packets).map(|_| vec![0u8; 65535]).collect();
        let mut msg_headers: Vec<libc::mmsghdr> = Vec::with_capacity(max_packets);
        let mut iovecs: Vec<libc::iovec> = Vec::with_capacity(max_packets);
        let mut sockaddrs: Vec<MaybeUninit<libc::sockaddr_storage>> = vec![MaybeUninit::uninit(); max_packets];

        // Setup message headers for recvmmsg
        for i in 0..max_packets {
            let iovec = libc::iovec {
                iov_base: buffers[i].as_mut_ptr() as *mut libc::c_void,
                iov_len: buffers[i].len(),
            };
            iovecs.push(iovec);

            let msg_hdr = libc::msghdr {
                msg_name: sockaddrs[i].as_mut_ptr() as *mut libc::c_void,
                msg_namelen: std::mem::size_of::<libc::sockaddr_storage>() as u32,
                msg_iov: &mut iovecs[i] as *mut libc::iovec,
                msg_iovlen: 1,
                msg_control: std::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
            };

            let mmsghdr = libc::mmsghdr {
                msg_hdr,
                msg_len: 0,
            };
            msg_headers.push(mmsghdr);
        }

        // Perform vectorized receive
        let fd = socket.as_raw_fd();
        let received = unsafe {
            libc::recvmmsg(
                fd,
                msg_headers.as_mut_ptr(),
                max_packets as u32,
                libc::MSG_DONTWAIT,
                std::ptr::null_mut(),
            )
        };

        if received < 0 {
            let errno = unsafe { *libc::__errno_location() };
            if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                return Ok(packets); // No packets available
            }
            return Err(QuicError::Io(std::io::Error::from_raw_os_error(errno)));
        }

        // Process received packets
        for i in 0..received as usize {
            let len = msg_headers[i].msg_len as usize;
            if len > 0 {
                let data = Bytes::copy_from_slice(&buffers[i][..len]);

                // Convert sockaddr to SocketAddr
                let addr = unsafe {
                    let sockaddr = sockaddrs[i].assume_init();
                    self.sockaddr_to_socketaddr(&sockaddr)?
                };

                let metadata = crate::zerocopy::PacketMetadata {
                    src_addr: addr,
                    dst_addr: socket.local_addr().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
                    timestamp: Instant::now(),
                    size: len,
                    qos: crate::zerocopy::QoSMarking::BestEffort,
                    needs_processing: true,
                    packet_type: crate::zerocopy::PacketTypeHint::Data,
                };

                let packet = PacketBuffer::new(data, metadata);
                packets.push((packet, addr));
            }
        }

        self.stats.vectorized_receives.fetch_add(1, Ordering::Relaxed);
        self.stats.packets_received.fetch_add(packets.len() as u64, Ordering::Relaxed);

        Ok(packets)
    }

    #[cfg(target_os = "linux")]
    unsafe fn sockaddr_to_socketaddr(&self, sockaddr: &libc::sockaddr_storage) -> QuicResult<SocketAddr> {
        match sockaddr.ss_family as i32 {
            libc::AF_INET => {
                let addr4 = sockaddr as *const _ as *const libc::sockaddr_in;
                let ip = std::net::Ipv4Addr::from(u32::from_be((*addr4).sin_addr.s_addr));
                let port = u16::from_be((*addr4).sin_port);
                Ok(SocketAddr::new(ip.into(), port))
            }
            libc::AF_INET6 => {
                let addr6 = sockaddr as *const _ as *const libc::sockaddr_in6;
                let ip = std::net::Ipv6Addr::from((*addr6).sin6_addr.s6_addr);
                let port = u16::from_be((*addr6).sin6_port);
                Ok(SocketAddr::new(ip.into(), port))
            }
            _ => Err(QuicError::Protocol("Unsupported address family".to_string())),
        }
    }

    /// Worker loop for processing batches
    async fn worker_loop(
        worker_id: usize,
        config: BatchConfig,
        memory_pool: Arc<AdvancedMemoryPool>,
        input_queue: parking_lot::Mutex<VecDeque<BatchItem>>,
        output_queue: parking_lot::Mutex<VecDeque<ProcessedBatch>>,
        batch_ready: Arc<Notify>,
        stats: BatchStats,
    ) {
        debug!("Batch worker {} started", worker_id);

        let mut last_batch_time = Instant::now();

        loop {
            // Wait for batch ready notification or timeout
            let timeout_future = tokio::time::sleep(config.batch_timeout);
            tokio::select! {
                _ = batch_ready.notified() => {},
                _ = timeout_future => {},
            }

            // Extract batch from input queue
            let batch = {
                let mut queue = input_queue.lock();
                let now = Instant::now();
                let should_process = queue.len() >= config.max_batch_size
                    || (queue.len() > 0 && now.duration_since(last_batch_time) >= config.batch_timeout);

                if should_process {
                    let batch_size = std::cmp::min(queue.len(), config.max_batch_size);
                    let batch: Vec<_> = (0..batch_size).map(|_| queue.pop_front().unwrap()).collect();
                    last_batch_time = now;
                    batch
                } else {
                    Vec::new()
                }
            };

            if batch.is_empty() {
                continue;
            }

            // Process the batch
            let start_time = Instant::now();
            let processed_batch = Self::process_batch_items(worker_id, batch, &memory_pool).await;
            let processing_time = start_time.elapsed();

            // Update statistics
            stats.batches_processed.fetch_add(1, Ordering::Relaxed);
            stats.total_processing_time.fetch_add(processing_time.as_nanos() as u64, Ordering::Relaxed);

            // Add to output queue
            {
                let mut queue = output_queue.lock();
                queue.push_back(processed_batch);
            }
        }
    }

    /// Process a batch of items
    async fn process_batch_items(
        worker_id: usize,
        batch: Vec<BatchItem>,
        memory_pool: &Arc<AdvancedMemoryPool>,
    ) -> ProcessedBatch {
        let batch_size = batch.len();
        let start_time = Instant::now();
        let mut processed_packets = Vec::with_capacity(batch_size);
        let mut errors = Vec::new();

        // Sort by priority for optimal processing order
        let mut sorted_batch = batch;
        sorted_batch.sort_by(|a, b| b.priority.cmp(&a.priority));

        // Process packets in parallel groups by priority
        let mut high_priority = Vec::new();
        let mut normal_priority = Vec::new();
        let mut low_priority = Vec::new();

        for item in sorted_batch {
            match item.priority {
                ProcessingPriority::High => high_priority.push(item),
                ProcessingPriority::Normal => normal_priority.push(item),
                ProcessingPriority::Low => low_priority.push(item),
            }
        }

        // Process high priority first
        for item in high_priority {
            match Self::process_single_item(item, memory_pool).await {
                Ok(result) => processed_packets.push(result),
                Err(e) => errors.push(e),
            }
        }

        // Process normal and low priority in parallel
        let normal_future = Self::process_priority_group(normal_priority, memory_pool);
        let low_future = Self::process_priority_group(low_priority, memory_pool);

        let (normal_results, low_results) = tokio::join!(normal_future, low_future);

        // Collect results
        for result in normal_results {
            match result {
                Ok(packet) => processed_packets.push(packet),
                Err(e) => errors.push(e),
            }
        }

        for result in low_results {
            match result {
                Ok(packet) => processed_packets.push(packet),
                Err(e) => errors.push(e),
            }
        }

        ProcessedBatch {
            worker_id,
            packets: processed_packets,
            errors,
            processing_time: start_time.elapsed(),
            batch_size,
        }
    }

    /// Process a group of items with the same priority
    async fn process_priority_group(
        items: Vec<BatchItem>,
        memory_pool: &Arc<AdvancedMemoryPool>,
    ) -> Vec<QuicResult<ProcessedPacket>> {
        let futures = items.into_iter().map(|item| Self::process_single_item(item, memory_pool));
        futures::future::join_all(futures).await
    }

    /// Process a single batch item
    async fn process_single_item(
        item: BatchItem,
        memory_pool: &Arc<AdvancedMemoryPool>,
    ) -> QuicResult<ProcessedPacket> {
        // Parse packet
        let packet = Packet::parse(&item.packet.data)
            .map_err(|e| QuicError::Protocol(format!("Failed to parse packet: {}", e)))?;

        // Validate packet
        if packet.data.len() < 4 {
            return Err(QuicError::Protocol("Packet too short".to_string()));
        }

        // Apply processing based on packet type and priority
        let processing_result = match item.priority {
            ProcessingPriority::High => Self::process_high_priority(&packet, &item).await,
            ProcessingPriority::Normal => Self::process_normal_priority(&packet, &item).await,
            ProcessingPriority::Low => Self::process_low_priority(&packet, &item).await,
        };

        Ok(ProcessedPacket {
            original_packet: item.packet,
            parsed_packet: packet,
            addr: item.addr,
            priority: item.priority,
            processing_result,
            latency: item.timestamp.elapsed(),
        })
    }

    async fn process_high_priority(packet: &Packet, item: &BatchItem) -> ProcessingResult {
        // High-priority processing (handshake, connection management)
        ProcessingResult::Processed
    }

    async fn process_normal_priority(packet: &Packet, item: &BatchItem) -> ProcessingResult {
        // Normal priority processing (data packets)
        ProcessingResult::Processed
    }

    async fn process_low_priority(packet: &Packet, item: &BatchItem) -> ProcessingResult {
        // Low priority processing (background tasks)
        ProcessingResult::Processed
    }

    /// Get processing statistics
    pub fn stats(&self) -> BatchStatsSnapshot {
        self.stats.snapshot()
    }

    /// Shutdown the batch processor
    pub async fn shutdown(self) -> QuicResult<()> {
        // Cancel all workers
        for worker in self.workers {
            worker.abort();
        }

        info!("Batch processor shutdown complete");
        Ok(())
    }
}

/// Item in the batch processing queue
#[derive(Debug)]
struct BatchItem {
    packet: PacketBuffer,
    addr: SocketAddr,
    priority: ProcessingPriority,
    timestamp: Instant,
}

/// Processing priority for packets
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProcessingPriority {
    Low = 0,
    Normal = 1,
    High = 2,
}

/// Result of processing a batch
#[derive(Debug)]
pub struct ProcessedBatch {
    pub worker_id: usize,
    pub packets: Vec<ProcessedPacket>,
    pub errors: Vec<QuicError>,
    pub processing_time: Duration,
    pub batch_size: usize,
}

/// Single processed packet result
#[derive(Debug)]
pub struct ProcessedPacket {
    pub original_packet: PacketBuffer,
    pub parsed_packet: Packet,
    pub addr: SocketAddr,
    pub priority: ProcessingPriority,
    pub processing_result: ProcessingResult,
    pub latency: Duration,
}

/// Result of packet processing
#[derive(Debug, Clone, PartialEq)]
pub enum ProcessingResult {
    Processed,
    Dropped { reason: String },
    Deferred { until: Instant },
    Error { error: String },
}

/// Batch processing statistics
#[derive(Debug, Clone)]
struct BatchStats {
    packets_submitted: AtomicU64,
    packets_received: AtomicU64,
    packets_processed: AtomicU64,
    batches_processed: AtomicU64,
    vectorized_receives: AtomicU64,
    total_processing_time: AtomicU64,
}

impl Default for BatchStats {
    fn default() -> Self {
        Self {
            packets_submitted: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
            packets_processed: AtomicU64::new(0),
            batches_processed: AtomicU64::new(0),
            vectorized_receives: AtomicU64::new(0),
            total_processing_time: AtomicU64::new(0),
        }
    }
}

impl BatchStats {
    fn snapshot(&self) -> BatchStatsSnapshot {
        BatchStatsSnapshot {
            packets_submitted: self.packets_submitted.load(Ordering::Relaxed),
            packets_received: self.packets_received.load(Ordering::Relaxed),
            packets_processed: self.packets_processed.load(Ordering::Relaxed),
            batches_processed: self.batches_processed.load(Ordering::Relaxed),
            vectorized_receives: self.vectorized_receives.load(Ordering::Relaxed),
            total_processing_time: Duration::from_nanos(self.total_processing_time.load(Ordering::Relaxed)),
        }
    }
}

/// Snapshot of batch processing statistics
#[derive(Debug, Clone)]
pub struct BatchStatsSnapshot {
    pub packets_submitted: u64,
    pub packets_received: u64,
    pub packets_processed: u64,
    pub batches_processed: u64,
    pub vectorized_receives: u64,
    pub total_processing_time: Duration,
}

impl BatchStatsSnapshot {
    /// Calculate average processing time per packet
    pub fn avg_processing_time_per_packet(&self) -> Duration {
        if self.packets_processed > 0 {
            self.total_processing_time / self.packets_processed as u32
        } else {
            Duration::ZERO
        }
    }

    /// Calculate average batch size
    pub fn avg_batch_size(&self) -> f64 {
        if self.batches_processed > 0 {
            self.packets_processed as f64 / self.batches_processed as f64
        } else {
            0.0
        }
    }

    /// Calculate throughput in packets per second
    pub fn throughput_pps(&self) -> f64 {
        if self.total_processing_time.as_secs_f64() > 0.0 {
            self.packets_processed as f64 / self.total_processing_time.as_secs_f64()
        } else {
            0.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_batch_processor_creation() {
        let config = BatchConfig::default();
        let processor = BatchProcessor::new(config);
        assert!(processor.is_ok());
    }

    #[tokio::test]
    async fn test_batch_submission() {
        let config = BatchConfig::default();
        let processor = BatchProcessor::new(config).unwrap();

        let data = Bytes::from("test packet");
        let metadata = crate::zerocopy::PacketMetadata {
            src_addr: SocketAddr::from_str("127.0.0.1:8080").unwrap(),
            dst_addr: SocketAddr::from_str("127.0.0.1:9090").unwrap(),
            timestamp: Instant::now(),
            size: data.len(),
            qos: crate::zerocopy::QoSMarking::BestEffort,
            needs_processing: true,
            packet_type: crate::zerocopy::PacketTypeHint::Data,
        };

        let packet = PacketBuffer::new(data, metadata);
        let addr = SocketAddr::from_str("127.0.0.1:8080").unwrap();

        let result = processor.submit_packet(packet, addr, ProcessingPriority::Normal);
        assert!(result.is_ok());

        let stats = processor.stats();
        assert_eq!(stats.packets_submitted, 1);
    }

    #[test]
    fn test_processing_priority_ordering() {
        assert!(ProcessingPriority::High > ProcessingPriority::Normal);
        assert!(ProcessingPriority::Normal > ProcessingPriority::Low);
    }

    #[test]
    fn test_batch_stats() {
        let stats = BatchStats::default();
        stats.packets_submitted.store(100, Ordering::Relaxed);
        stats.packets_processed.store(95, Ordering::Relaxed);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.packets_submitted, 100);
        assert_eq!(snapshot.packets_processed, 95);
    }
}