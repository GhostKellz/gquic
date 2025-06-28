use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, info};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionMetrics {
    pub total_connections: u64,
    pub active_connections: u64,
    pub failed_connections: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub average_latency_ms: f64,
    pub connection_duration_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamMetrics {
    pub total_bi_streams: u64,
    pub total_uni_streams: u64,
    pub active_bi_streams: u64,
    pub active_uni_streams: u64,
    pub stream_errors: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub cpu_usage_percent: f64,
    pub memory_usage_bytes: u64,
    pub network_throughput_bps: u64,
    pub packet_loss_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicMetrics {
    pub connection: ConnectionMetrics,
    pub stream: StreamMetrics,
    pub performance: PerformanceMetrics,
    pub timestamp: u64,
    pub uptime_seconds: u64,
}

#[derive(Debug)]
pub struct MetricsCollector {
    start_time: Instant,
    
    // Connection metrics
    total_connections: AtomicU64,
    active_connections: AtomicU64,
    failed_connections: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    
    // Stream metrics
    total_bi_streams: AtomicU64,
    total_uni_streams: AtomicU64,
    active_bi_streams: AtomicU64,
    active_uni_streams: AtomicU64,
    stream_errors: AtomicU64,
    
    // Latency tracking
    latency_samples: Arc<RwLock<Vec<Duration>>>,
    
    // Connection duration tracking
    connection_durations: Arc<RwLock<Vec<Duration>>>,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            total_connections: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            failed_connections: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            total_bi_streams: AtomicU64::new(0),
            total_uni_streams: AtomicU64::new(0),
            active_bi_streams: AtomicU64::new(0),
            active_uni_streams: AtomicU64::new(0),
            stream_errors: AtomicU64::new(0),
            latency_samples: Arc::new(RwLock::new(Vec::new())),
            connection_durations: Arc::new(RwLock::new(Vec::new())),
        }
    }

    // Connection metrics
    pub fn connection_established(&self) {
        self.total_connections.fetch_add(1, Ordering::Relaxed);
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        debug!("Connection established, total: {}, active: {}", 
               self.total_connections.load(Ordering::Relaxed),
               self.active_connections.load(Ordering::Relaxed));
    }

    pub fn connection_closed(&self, duration: Duration) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
        
        tokio::spawn({
            let durations = Arc::clone(&self.connection_durations);
            async move {
                let mut durations = durations.write().await;
                durations.push(duration);
                
                // Keep only last 1000 samples
                if durations.len() > 1000 {
                    durations.remove(0);
                }
            }
        });
        
        debug!("Connection closed, duration: {:?}, active: {}", 
               duration, self.active_connections.load(Ordering::Relaxed));
    }

    pub fn connection_failed(&self) {
        self.failed_connections.fetch_add(1, Ordering::Relaxed);
        debug!("Connection failed, total failures: {}", 
               self.failed_connections.load(Ordering::Relaxed));
    }

    // Data metrics
    pub fn bytes_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn bytes_received(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    // Stream metrics
    pub fn bi_stream_opened(&self) {
        self.total_bi_streams.fetch_add(1, Ordering::Relaxed);
        self.active_bi_streams.fetch_add(1, Ordering::Relaxed);
    }

    pub fn bi_stream_closed(&self) {
        self.active_bi_streams.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn uni_stream_opened(&self) {
        self.total_uni_streams.fetch_add(1, Ordering::Relaxed);
        self.active_uni_streams.fetch_add(1, Ordering::Relaxed);
    }

    pub fn uni_stream_closed(&self) {
        self.active_uni_streams.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn stream_error(&self) {
        self.stream_errors.fetch_add(1, Ordering::Relaxed);
    }

    // Latency tracking
    pub fn record_latency(&self, latency: Duration) {
        tokio::spawn({
            let samples = Arc::clone(&self.latency_samples);
            async move {
                let mut samples = samples.write().await;
                samples.push(latency);
                
                // Keep only last 1000 samples
                if samples.len() > 1000 {
                    samples.remove(0);
                }
            }
        });
    }

    // Get current metrics snapshot
    pub async fn get_metrics(&self) -> QuicMetrics {
        let latency_samples = self.latency_samples.read().await;
        let connection_durations = self.connection_durations.read().await;
        
        let average_latency_ms = if latency_samples.is_empty() {
            0.0
        } else {
            let total_ms: f64 = latency_samples.iter()
                .map(|d| d.as_secs_f64() * 1000.0)
                .sum();
            total_ms / latency_samples.len() as f64
        };

        let average_connection_duration_ms = if connection_durations.is_empty() {
            0.0
        } else {
            let total_ms: f64 = connection_durations.iter()
                .map(|d| d.as_secs_f64() * 1000.0)
                .sum();
            total_ms / connection_durations.len() as f64
        };

        QuicMetrics {
            connection: ConnectionMetrics {
                total_connections: self.total_connections.load(Ordering::Relaxed),
                active_connections: self.active_connections.load(Ordering::Relaxed),
                failed_connections: self.failed_connections.load(Ordering::Relaxed),
                bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
                bytes_received: self.bytes_received.load(Ordering::Relaxed),
                average_latency_ms,
                connection_duration_ms: average_connection_duration_ms,
            },
            stream: StreamMetrics {
                total_bi_streams: self.total_bi_streams.load(Ordering::Relaxed),
                total_uni_streams: self.total_uni_streams.load(Ordering::Relaxed),
                active_bi_streams: self.active_bi_streams.load(Ordering::Relaxed),
                active_uni_streams: self.active_uni_streams.load(Ordering::Relaxed),
                stream_errors: self.stream_errors.load(Ordering::Relaxed),
            },
            performance: self.get_performance_metrics().await,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            uptime_seconds: self.start_time.elapsed().as_secs(),
        }
    }

    async fn get_performance_metrics(&self) -> PerformanceMetrics {
        // Basic implementation - in production, integrate with system monitoring
        PerformanceMetrics {
            cpu_usage_percent: 0.0,     // TODO: Implement actual CPU monitoring
            memory_usage_bytes: 0,      // TODO: Implement actual memory monitoring
            network_throughput_bps: 0,  // TODO: Calculate from bytes_sent/received over time
            packet_loss_rate: 0.0,     // TODO: Implement packet loss detection
        }
    }

    pub fn log_summary(&self) {
        let total_conn = self.total_connections.load(Ordering::Relaxed);
        let active_conn = self.active_connections.load(Ordering::Relaxed);
        let failed_conn = self.failed_connections.load(Ordering::Relaxed);
        let bytes_sent = self.bytes_sent.load(Ordering::Relaxed);
        let bytes_recv = self.bytes_received.load(Ordering::Relaxed);
        
        info!(
            "📊 Metrics Summary - Total: {} | Active: {} | Failed: {} | Sent: {} bytes | Recv: {} bytes",
            total_conn, active_conn, failed_conn, bytes_sent, bytes_recv
        );
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

// Global metrics instance
lazy_static::lazy_static! {
    pub static ref METRICS: MetricsCollector = MetricsCollector::new();
}

#[cfg(feature = "metrics")]
pub fn get_metrics() -> &'static MetricsCollector {
    &METRICS
}