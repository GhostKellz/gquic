//! Gaming-optimized QUIC extensions for GhostPanel
//!
//! This module provides specialized QUIC optimizations for gaming container management:
//! - Ultra-low latency transport for real-time container operations
//! - Gaming-aware congestion control that doesn't interfere with gaming workloads
//! - Container-specific stream prioritization and multiplexing
//! - GPU passthrough optimizations and telemetry integration

use std::sync::Arc;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use tokio::sync::{RwLock, Mutex};
use bytes::Bytes;
use tracing::{debug, warn, error, info};

use crate::QuicResult;
use crate::quic::{Connection, StreamId};
use crate::quic::Packet;

/// Gaming-optimized congestion control parameters
#[derive(Debug, Clone)]
pub struct GamingCongestionConfig {
    /// Maximum allowed congestion window during gaming sessions
    pub max_gaming_cwnd: u32,
    /// Gaming traffic detection threshold (packets/sec)
    pub gaming_threshold_pps: u64,
    /// Minimum RTT target for gaming optimization
    pub target_gaming_rtt: Duration,
    /// Gaming session timeout
    pub gaming_session_timeout: Duration,
}

impl Default for GamingCongestionConfig {
    fn default() -> Self {
        Self {
            max_gaming_cwnd: 32768, // Conservative for gaming
            gaming_threshold_pps: 100, // Detect active gaming
            target_gaming_rtt: Duration::from_millis(5), // Sub-5ms target
            gaming_session_timeout: Duration::from_secs(30),
        }
    }
}

/// Container-aware stream priorities
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerStreamPriority {
    /// Critical container operations (start/stop/kill)
    Critical = 0,
    /// Container health checks and monitoring
    Health = 1,
    /// Real-time gaming telemetry
    GamingTelemetry = 2,
    /// Container logs and stdout/stderr
    Logs = 3,
    /// Bulk operations (image pulls, backups)
    Bulk = 4,
}

/// Gaming session tracking for congestion control awareness
#[derive(Debug)]
pub struct GamingSession {
    pub container_id: String,
    pub session_start: Instant,
    pub last_activity: Instant,
    pub packet_count: u64,
    pub gpu_utilization: f32,
    pub input_lag_ms: f32,
}

/// Ultra-low latency QUIC transport optimizations for gaming containers
#[derive(Debug)]
pub struct GamingOptimizedTransport {
    /// Gaming congestion control configuration
    config: GamingCongestionConfig,
    /// Active gaming sessions tracking
    gaming_sessions: Arc<RwLock<HashMap<String, GamingSession>>>,
    /// Container stream priorities
    stream_priorities: Arc<RwLock<HashMap<StreamId, ContainerStreamPriority>>>,
    /// Gaming mode flag
    gaming_mode_active: Arc<Mutex<bool>>,
    /// High-precision timing for sub-microsecond operations
    precision_timer: Arc<Mutex<Instant>>,
}

impl GamingOptimizedTransport {
    pub fn new(config: GamingCongestionConfig) -> Self {
        Self {
            config,
            gaming_sessions: Arc::new(RwLock::new(HashMap::new())),
            stream_priorities: Arc::new(RwLock::new(HashMap::new())),
            gaming_mode_active: Arc::new(Mutex::new(false)),
            precision_timer: Arc::new(Mutex::new(Instant::now())),
        }
    }

    /// Register a new gaming session for congestion control awareness
    pub async fn register_gaming_session(&self, container_id: String, gpu_info: Option<GpuInfo>) -> QuicResult<()> {
        let mut sessions = self.gaming_sessions.write().await;
        let session = GamingSession {
            container_id: container_id.clone(),
            session_start: Instant::now(),
            last_activity: Instant::now(),
            packet_count: 0,
            gpu_utilization: gpu_info.map_or(0.0, |g| g.utilization_percent),
            input_lag_ms: 0.0,
        };

        sessions.insert(container_id, session);

        // Enable gaming mode if we have active gaming sessions
        if !sessions.is_empty() {
            *self.gaming_mode_active.lock().await = true;
            info!("Gaming mode activated - {} active sessions", sessions.len());
        }

        Ok(())
    }

    /// Update gaming session telemetry (called from GPU monitoring)
    pub async fn update_gaming_telemetry(&self, container_id: &str, telemetry: GamingTelemetry) -> QuicResult<()> {
        let mut sessions = self.gaming_sessions.write().await;
        if let Some(session) = sessions.get_mut(container_id) {
            session.last_activity = Instant::now();
            session.gpu_utilization = telemetry.gpu_utilization;
            session.input_lag_ms = telemetry.input_lag_ms;
            session.packet_count += 1;

            debug!("Gaming telemetry updated for {}: GPU {}%, Input lag {}ms",
                   container_id, telemetry.gpu_utilization, telemetry.input_lag_ms);
        }
        Ok(())
    }

    /// Set stream priority for container-aware scheduling
    pub async fn set_stream_priority(&self, stream_id: StreamId, priority: ContainerStreamPriority) {
        let mut priorities = self.stream_priorities.write().await;
        priorities.insert(stream_id, priority);

        debug!("Stream {} priority set to {:?}", stream_id.value(), priority);
    }

    /// Gaming-aware congestion control adjustment
    pub async fn adjust_congestion_window(&self, connection: &mut Connection, rtt: Duration) -> QuicResult<u32> {
        let gaming_active = *self.gaming_mode_active.lock().await;

        if gaming_active {
            // Conservative congestion control during gaming sessions
            let gaming_cwnd = if rtt > self.config.target_gaming_rtt {
                // Reduce window if RTT is above target
                (self.config.max_gaming_cwnd as f64 * 0.8) as u32
            } else {
                self.config.max_gaming_cwnd
            };

            debug!("Gaming-aware CWND adjustment: {} (RTT: {:?})", gaming_cwnd, rtt);
            Ok(gaming_cwnd)
        } else {
            // Standard aggressive congestion control when no gaming sessions
            Ok(65536) // Standard maximum
        }
    }

    /// Priority-based packet scheduling for container streams
    pub async fn schedule_packet(&self, packet: &mut Packet, stream_id: StreamId) -> QuicResult<u8> {
        let priorities = self.stream_priorities.read().await;
        let priority = priorities.get(&stream_id).copied().unwrap_or(ContainerStreamPriority::Bulk);

        // Set QUIC packet priority based on container stream type
        let quic_priority = match priority {
            ContainerStreamPriority::Critical => 0,        // Highest priority
            ContainerStreamPriority::Health => 1,
            ContainerStreamPriority::GamingTelemetry => 2,
            ContainerStreamPriority::Logs => 3,
            ContainerStreamPriority::Bulk => 4,           // Lowest priority
        };

        // Add gaming boost for telemetry during active sessions
        let gaming_active = *self.gaming_mode_active.lock().await;
        let final_priority = if gaming_active && priority == ContainerStreamPriority::GamingTelemetry {
            0 // Boost gaming telemetry to critical during active sessions
        } else {
            quic_priority
        };

        Ok(final_priority)
    }

    /// Clean up expired gaming sessions
    pub async fn cleanup_expired_sessions(&self) -> QuicResult<()> {
        let mut sessions = self.gaming_sessions.write().await;
        let now = Instant::now();

        sessions.retain(|container_id, session| {
            let expired = now.duration_since(session.last_activity) > self.config.gaming_session_timeout;
            if expired {
                info!("Gaming session expired for container: {}", container_id);
            }
            !expired
        });

        // Disable gaming mode if no active sessions
        if sessions.is_empty() {
            *self.gaming_mode_active.lock().await = false;
            info!("Gaming mode deactivated - no active sessions");
        }

        Ok(())
    }

    /// Get current gaming mode status and session count
    pub async fn get_gaming_status(&self) -> (bool, usize) {
        let gaming_active = *self.gaming_mode_active.lock().await;
        let session_count = self.gaming_sessions.read().await.len();
        (gaming_active, session_count)
    }
}

/// GPU information for gaming optimization
#[derive(Debug, Clone)]
pub struct GpuInfo {
    pub device_id: String,
    pub utilization_percent: f32,
    pub memory_used_mb: u64,
    pub memory_total_mb: u64,
    pub temperature_c: f32,
}

/// Real-time gaming telemetry data
#[derive(Debug, Clone)]
pub struct GamingTelemetry {
    pub gpu_utilization: f32,
    pub frame_time_ms: f32,
    pub input_lag_ms: f32,
    pub network_latency_us: u64,
    pub packet_loss_percent: f32,
}

/// Container-aware QUIC stream multiplexer
#[derive(Debug)]
pub struct ContainerStreamMultiplexer {
    /// Gaming transport optimizations
    gaming_transport: Arc<GamingOptimizedTransport>,
    /// Per-container stream tracking
    container_streams: Arc<RwLock<HashMap<String, Vec<StreamId>>>>,
    /// Stream-to-container mapping
    stream_containers: Arc<RwLock<HashMap<StreamId, String>>>,
}

impl ContainerStreamMultiplexer {
    pub fn new(gaming_transport: Arc<GamingOptimizedTransport>) -> Self {
        Self {
            gaming_transport,
            container_streams: Arc::new(RwLock::new(HashMap::new())),
            stream_containers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a new container-specific stream with priority
    pub async fn create_container_stream(
        &self,
        connection: &mut Connection,
        container_id: String,
        priority: ContainerStreamPriority,
    ) -> QuicResult<StreamId> {
        // Create the stream through the connection
        let stream_id = connection.open_stream(true).await?; // Bidirectional stream

        // Set priority for gaming-aware scheduling
        self.gaming_transport.set_stream_priority(stream_id, priority).await;

        // Track container association
        {
            let mut container_streams = self.container_streams.write().await;
            container_streams.entry(container_id.clone()).or_insert_with(Vec::new).push(stream_id);
        }

        {
            let mut stream_containers = self.stream_containers.write().await;
            stream_containers.insert(stream_id, container_id.clone());
        }

        info!("Created {:?} priority stream {} for container {}", priority, stream_id.value(), container_id);
        Ok(stream_id)
    }

    /// Send data with container-aware prioritization
    pub async fn send_container_data(
        &self,
        connection: &mut Connection,
        stream_id: StreamId,
        data: Bytes,
    ) -> QuicResult<()> {
        // Gaming-aware packet scheduling happens automatically through the transport layer
        connection.send_stream_data(stream_id, data).await.map_err(Into::into)
    }

    /// Get all streams for a specific container
    pub async fn get_container_streams(&self, container_id: &str) -> Vec<StreamId> {
        let streams = self.container_streams.read().await;
        streams.get(container_id).cloned().unwrap_or_default()
    }

    /// Close all streams for a container (when container stops)
    pub async fn close_container_streams(&self, connection: &mut Connection, container_id: &str) -> QuicResult<()> {
        let stream_ids = self.get_container_streams(container_id).await;

        for stream_id in &stream_ids {
            if let Err(e) = connection.close_stream(*stream_id).await {
                warn!("Failed to close stream {} for container {}: {}", stream_id.value(), container_id, e);
            }
        }

        // Clean up tracking
        {
            let mut container_streams = self.container_streams.write().await;
            container_streams.remove(container_id);
        }

        {
            let mut stream_containers = self.stream_containers.write().await;
            for stream_id in stream_ids {
                stream_containers.remove(&stream_id);
            }
        }

        info!("Closed all streams for container: {}", container_id);
        Ok(())
    }
}

/// High-precision timing utilities for sub-microsecond operations
pub struct PrecisionTiming;

impl PrecisionTiming {
    /// Get high-precision timestamp for ultra-low latency measurements
    pub fn now_microseconds() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64
    }

    /// Measure operation latency in microseconds
    pub fn measure_latency<F, R>(operation: F) -> (R, u64)
    where
        F: FnOnce() -> R,
    {
        let start = Self::now_microseconds();
        let result = operation();
        let end = Self::now_microseconds();
        (result, end - start)
    }

    /// Sleep with microsecond precision (for rate limiting)
    pub async fn sleep_microseconds(microseconds: u64) {
        tokio::time::sleep(Duration::from_micros(microseconds)).await;
    }
}

/// Zero-copy buffer management for high-performance container operations
#[derive(Debug)]
pub struct ZeroCopyBufferPool {
    /// Pre-allocated buffer pool
    buffers: Arc<Mutex<Vec<Vec<u8>>>>,
    /// Buffer size for pool management
    buffer_size: usize,
    /// Maximum pool size to prevent memory bloat
    max_pool_size: usize,
}

impl ZeroCopyBufferPool {
    pub fn new(buffer_size: usize, initial_size: usize, max_size: usize) -> Self {
        let mut buffers = Vec::with_capacity(initial_size);
        for _ in 0..initial_size {
            buffers.push(vec![0u8; buffer_size]);
        }

        Self {
            buffers: Arc::new(Mutex::new(buffers)),
            buffer_size,
            max_pool_size: max_size,
        }
    }

    /// Get a buffer from the pool (zero-copy when available)
    pub async fn get_buffer(&self) -> Vec<u8> {
        let mut buffers = self.buffers.lock().await;
        buffers.pop().unwrap_or_else(|| vec![0u8; self.buffer_size])
    }

    /// Return a buffer to the pool
    pub async fn return_buffer(&self, mut buffer: Vec<u8>) {
        if buffer.len() == self.buffer_size {
            let mut buffers = self.buffers.lock().await;
            if buffers.len() < self.max_pool_size {
                buffer.clear();
                buffer.resize(self.buffer_size, 0);
                buffers.push(buffer);
            }
        }
    }

    /// Get current pool statistics
    pub async fn get_stats(&self) -> (usize, usize) {
        let buffers = self.buffers.lock().await;
        (buffers.len(), self.max_pool_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;

    #[tokio::test]
    async fn test_gaming_session_management() {
        let config = GamingCongestionConfig::default();
        let transport = GamingOptimizedTransport::new(config);

        // Register gaming session
        transport.register_gaming_session("test-container".to_string(), None).await.unwrap();

        let (gaming_active, session_count) = transport.get_gaming_status().await;
        assert!(gaming_active);
        assert_eq!(session_count, 1);

        // Update telemetry
        let telemetry = GamingTelemetry {
            gpu_utilization: 85.0,
            frame_time_ms: 16.7,
            input_lag_ms: 3.2,
            network_latency_us: 2500,
            packet_loss_percent: 0.1,
        };
        transport.update_gaming_telemetry("test-container", telemetry).await.unwrap();
    }

    #[tokio::test]
    async fn test_precision_timing() {
        let (result, latency_us) = PrecisionTiming::measure_latency(|| {
            std::thread::sleep(Duration::from_micros(100));
            42
        });

        assert_eq!(result, 42);
        assert!(latency_us >= 100);
        assert!(latency_us < 1000); // Should be well under 1ms
    }

    #[tokio::test]
    async fn test_zero_copy_buffer_pool() {
        let pool = ZeroCopyBufferPool::new(1024, 5, 10);

        let buffer = pool.get_buffer().await;
        assert_eq!(buffer.len(), 1024);

        let (available, max_size) = pool.get_stats().await;
        assert_eq!(available, 4); // One buffer taken
        assert_eq!(max_size, 10);

        pool.return_buffer(buffer).await;

        let (available, _) = pool.get_stats().await;
        assert_eq!(available, 5); // Buffer returned
    }
}