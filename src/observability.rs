//! Comprehensive Observability and Metrics
//!
//! This module provides extensive monitoring, metrics collection, and diagnostics
//! to make GQUIC the most observable QUIC implementation.

use crate::quic::error::{QuicError, Result};
use crate::quic::connection::ConnectionId;
use crate::mesh::PeerId;
use std::collections::HashMap;
use std::sync::{Arc, atomic::{AtomicU64, AtomicUsize, Ordering}};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, info, warn, error};
use serde::{Serialize, Deserialize};

/// Comprehensive metrics collector for GQUIC
#[derive(Debug)]
pub struct MetricsCollector {
    /// Core QUIC metrics
    quic_metrics: Arc<RwLock<QuicMetrics>>,
    /// Connection-specific metrics
    connection_metrics: Arc<RwLock<HashMap<ConnectionId, ConnectionMetrics>>>,
    /// Peer-specific metrics for mesh networking
    peer_metrics: Arc<RwLock<HashMap<PeerId, PeerMetrics>>>,
    /// Performance metrics
    performance_metrics: Arc<PerformanceMetrics>,
    /// Security metrics
    security_metrics: Arc<SecurityMetrics>,
    /// Custom metrics
    custom_metrics: Arc<RwLock<HashMap<String, CustomMetric>>>,
    /// Histogram buckets for latency measurements
    latency_histogram: Arc<RwLock<LatencyHistogram>>,
}

/// Core QUIC protocol metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicMetrics {
    /// Total packets sent
    pub packets_sent: u64,
    /// Total packets received
    pub packets_received: u64,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Packets lost
    pub packets_lost: u64,
    /// Packets retransmitted
    pub packets_retransmitted: u64,
    /// Active connections
    pub active_connections: usize,
    /// Total connections established
    pub total_connections: u64,
    /// Failed connections
    pub failed_connections: u64,
    /// Stream statistics
    pub streams_opened: u64,
    /// Streams closed
    pub streams_closed: u64,
    /// 0-RTT packets sent
    pub zero_rtt_packets_sent: u64,
    /// 0-RTT packets accepted
    pub zero_rtt_packets_accepted: u64,
    /// Handshake failures
    pub handshake_failures: u64,
}

impl Default for QuicMetrics {
    fn default() -> Self {
        Self {
            packets_sent: 0,
            packets_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
            packets_lost: 0,
            packets_retransmitted: 0,
            active_connections: 0,
            total_connections: 0,
            failed_connections: 0,
            streams_opened: 0,
            streams_closed: 0,
            zero_rtt_packets_sent: 0,
            zero_rtt_packets_accepted: 0,
            handshake_failures: 0,
        }
    }
}

/// Per-connection metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionMetrics {
    pub connection_id: String,
    pub established_at: SystemTime,
    pub last_activity: SystemTime,
    pub rtt: Duration,
    pub rtt_variance: Duration,
    pub congestion_window: u64,
    pub bytes_in_flight: u64,
    pub packet_loss_rate: f64,
    pub throughput_bps: u64,
    pub stream_count: usize,
}

/// Per-peer metrics for mesh networking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerMetrics {
    pub peer_id: String,
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
    pub connection_count: usize,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub average_latency: Duration,
    pub connection_failures: u64,
    pub successful_handshakes: u64,
}

/// Performance metrics
#[derive(Debug)]
pub struct PerformanceMetrics {
    /// CPU usage percentage
    pub cpu_usage: AtomicU64,
    /// Memory usage in bytes
    pub memory_usage: AtomicU64,
    /// Packets per second
    pub packets_per_second: AtomicU64,
    /// Bytes per second
    pub bytes_per_second: AtomicU64,
    /// Packet processing latency
    pub processing_latency_ns: AtomicU64,
    /// Encryption overhead
    pub encryption_overhead_ns: AtomicU64,
    /// Connection setup time
    pub connection_setup_time_ms: AtomicU64,
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self {
            cpu_usage: AtomicU64::new(0),
            memory_usage: AtomicU64::new(0),
            packets_per_second: AtomicU64::new(0),
            bytes_per_second: AtomicU64::new(0),
            processing_latency_ns: AtomicU64::new(0),
            encryption_overhead_ns: AtomicU64::new(0),
            connection_setup_time_ms: AtomicU64::new(0),
        }
    }
}

/// Security-related metrics
#[derive(Debug)]
pub struct SecurityMetrics {
    /// Authentication failures
    pub auth_failures: AtomicU64,
    /// Certificate verification failures
    pub cert_failures: AtomicU64,
    /// Replay attacks detected
    pub replay_attacks: AtomicU64,
    /// Rate limit violations
    pub rate_limit_violations: AtomicU64,
    /// Suspicious connection attempts
    pub suspicious_connections: AtomicU64,
    /// Crypto failures
    pub crypto_failures: AtomicU64,
}

impl Default for SecurityMetrics {
    fn default() -> Self {
        Self {
            auth_failures: AtomicU64::new(0),
            cert_failures: AtomicU64::new(0),
            replay_attacks: AtomicU64::new(0),
            rate_limit_violations: AtomicU64::new(0),
            suspicious_connections: AtomicU64::new(0),
            crypto_failures: AtomicU64::new(0),
        }
    }
}

/// Custom metric value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CustomMetric {
    Counter(u64),
    Gauge(f64),
    Histogram(Vec<f64>),
    Timer(Duration),
}

/// Latency histogram for detailed latency analysis
#[derive(Debug)]
pub struct LatencyHistogram {
    /// Buckets for different latency ranges (in microseconds)
    buckets: Vec<(u64, AtomicU64)>,
    /// Total samples
    total_samples: AtomicU64,
    /// Sum of all latencies for average calculation
    sum_latency_us: AtomicU64,
}

impl LatencyHistogram {
    fn new() -> Self {
        // Create buckets for different latency ranges
        let bucket_boundaries = vec![
            10, 50, 100, 500, 1000, 5000, 10000, 50000, 100000, 500000, 1000000
        ];

        let buckets = bucket_boundaries.into_iter()
            .map(|boundary| (boundary, AtomicU64::new(0)))
            .collect();

        Self {
            buckets,
            total_samples: AtomicU64::new(0),
            sum_latency_us: AtomicU64::new(0),
        }
    }

    fn record(&self, latency: Duration) {
        let latency_us = latency.as_micros() as u64;

        // Find appropriate bucket
        for (boundary, counter) in &self.buckets {
            if latency_us <= *boundary {
                counter.fetch_add(1, Ordering::Relaxed);
                break;
            }
        }

        self.total_samples.fetch_add(1, Ordering::Relaxed);
        self.sum_latency_us.fetch_add(latency_us, Ordering::Relaxed);
    }

    fn percentile(&self, p: f64) -> Option<Duration> {
        let total = self.total_samples.load(Ordering::Relaxed);
        if total == 0 {
            return None;
        }

        let target = (total as f64 * p) as u64;
        let mut cumulative = 0;

        for (boundary, counter) in &self.buckets {
            cumulative += counter.load(Ordering::Relaxed);
            if cumulative >= target {
                return Some(Duration::from_micros(*boundary));
            }
        }

        None
    }

    fn average(&self) -> Option<Duration> {
        let total = self.total_samples.load(Ordering::Relaxed);
        if total == 0 {
            return None;
        }

        let sum = self.sum_latency_us.load(Ordering::Relaxed);
        Some(Duration::from_micros(sum / total))
    }
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new() -> Self {
        Self {
            quic_metrics: Arc::new(RwLock::new(QuicMetrics::default())),
            connection_metrics: Arc::new(RwLock::new(HashMap::new())),
            peer_metrics: Arc::new(RwLock::new(HashMap::new())),
            performance_metrics: Arc::new(PerformanceMetrics::default()),
            security_metrics: Arc::new(SecurityMetrics::default()),
            custom_metrics: Arc::new(RwLock::new(HashMap::new())),
            latency_histogram: Arc::new(RwLock::new(LatencyHistogram::new())),
        }
    }

    /// Record packet sent
    pub async fn record_packet_sent(&self, bytes: usize) {
        let mut metrics = self.quic_metrics.write().await;
        metrics.packets_sent += 1;
        metrics.bytes_sent += bytes as u64;

        // Update performance metrics
        self.performance_metrics.bytes_per_second.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Record packet received
    pub async fn record_packet_received(&self, bytes: usize) {
        let mut metrics = self.quic_metrics.write().await;
        metrics.packets_received += 1;
        metrics.bytes_received += bytes as u64;
    }

    /// Record packet loss
    pub async fn record_packet_loss(&self, count: u64) {
        let mut metrics = self.quic_metrics.write().await;
        metrics.packets_lost += count;
    }

    /// Record connection established
    pub async fn record_connection_established(&self, connection_id: ConnectionId) {
        let mut metrics = self.quic_metrics.write().await;
        metrics.active_connections += 1;
        metrics.total_connections += 1;

        // Add connection-specific metrics
        let connection_metrics = ConnectionMetrics {
            connection_id: connection_id.to_string(),
            established_at: SystemTime::now(),
            last_activity: SystemTime::now(),
            rtt: Duration::from_millis(0),
            rtt_variance: Duration::from_millis(0),
            congestion_window: 1200, // Initial window
            bytes_in_flight: 0,
            packet_loss_rate: 0.0,
            throughput_bps: 0,
            stream_count: 0,
        };

        self.connection_metrics.write().await.insert(connection_id, connection_metrics);
    }

    /// Record connection closed
    pub async fn record_connection_closed(&self, connection_id: &ConnectionId) {
        let mut metrics = self.quic_metrics.write().await;
        metrics.active_connections = metrics.active_connections.saturating_sub(1);

        // Remove connection-specific metrics
        self.connection_metrics.write().await.remove(connection_id);
    }

    /// Record latency measurement
    pub async fn record_latency(&self, latency: Duration) {
        self.latency_histogram.read().await.record(latency);
    }

    /// Record security event
    pub fn record_auth_failure(&self) {
        self.security_metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_rate_limit_violation(&self) {
        self.security_metrics.rate_limit_violations.fetch_add(1, Ordering::Relaxed);
    }

    /// Record custom metric
    pub async fn record_custom_metric(&self, name: String, value: CustomMetric) {
        self.custom_metrics.write().await.insert(name, value);
    }

    /// Get current QUIC metrics
    pub async fn get_quic_metrics(&self) -> QuicMetrics {
        self.quic_metrics.read().await.clone()
    }

    /// Get performance summary
    pub fn get_performance_summary(&self) -> PerformanceSummary {
        PerformanceSummary {
            cpu_usage_percent: self.performance_metrics.cpu_usage.load(Ordering::Relaxed) as f64 / 100.0,
            memory_usage_mb: self.performance_metrics.memory_usage.load(Ordering::Relaxed) as f64 / (1024.0 * 1024.0),
            packets_per_second: self.performance_metrics.packets_per_second.load(Ordering::Relaxed),
            throughput_mbps: self.performance_metrics.bytes_per_second.load(Ordering::Relaxed) as f64 * 8.0 / (1024.0 * 1024.0),
            processing_latency_us: self.performance_metrics.processing_latency_ns.load(Ordering::Relaxed) as f64 / 1000.0,
        }
    }

    /// Get latency statistics
    pub async fn get_latency_stats(&self) -> LatencyStats {
        let histogram = self.latency_histogram.read().await;
        LatencyStats {
            average: histogram.average(),
            p50: histogram.percentile(0.5),
            p95: histogram.percentile(0.95),
            p99: histogram.percentile(0.99),
            p999: histogram.percentile(0.999),
            total_samples: histogram.total_samples.load(Ordering::Relaxed),
        }
    }

    /// Export metrics in Prometheus format
    pub async fn export_prometheus(&self) -> String {
        let mut output = String::new();

        // QUIC metrics
        let quic_metrics = self.quic_metrics.read().await;
        output.push_str(&format!("# HELP gquic_packets_sent_total Total packets sent\n"));
        output.push_str(&format!("# TYPE gquic_packets_sent_total counter\n"));
        output.push_str(&format!("gquic_packets_sent_total {}\n", quic_metrics.packets_sent));

        output.push_str(&format!("# HELP gquic_packets_received_total Total packets received\n"));
        output.push_str(&format!("# TYPE gquic_packets_received_total counter\n"));
        output.push_str(&format!("gquic_packets_received_total {}\n", quic_metrics.packets_received));

        output.push_str(&format!("# HELP gquic_bytes_sent_total Total bytes sent\n"));
        output.push_str(&format!("# TYPE gquic_bytes_sent_total counter\n"));
        output.push_str(&format!("gquic_bytes_sent_total {}\n", quic_metrics.bytes_sent));

        output.push_str(&format!("# HELP gquic_active_connections Current active connections\n"));
        output.push_str(&format!("# TYPE gquic_active_connections gauge\n"));
        output.push_str(&format!("gquic_active_connections {}\n", quic_metrics.active_connections));

        // Performance metrics
        let cpu_usage = self.performance_metrics.cpu_usage.load(Ordering::Relaxed);
        output.push_str(&format!("# HELP gquic_cpu_usage_percent CPU usage percentage\n"));
        output.push_str(&format!("# TYPE gquic_cpu_usage_percent gauge\n"));
        output.push_str(&format!("gquic_cpu_usage_percent {}\n", cpu_usage as f64 / 100.0));

        // Security metrics
        let auth_failures = self.security_metrics.auth_failures.load(Ordering::Relaxed);
        output.push_str(&format!("# HELP gquic_auth_failures_total Authentication failures\n"));
        output.push_str(&format!("# TYPE gquic_auth_failures_total counter\n"));
        output.push_str(&format!("gquic_auth_failures_total {}\n", auth_failures));

        // Latency histogram
        let histogram = self.latency_histogram.read().await;
        output.push_str(&format!("# HELP gquic_latency_seconds Latency histogram\n"));
        output.push_str(&format!("# TYPE gquic_latency_seconds histogram\n"));

        let mut cumulative = 0;
        for (boundary, counter) in &histogram.buckets {
            cumulative += counter.load(Ordering::Relaxed);
            let boundary_seconds = *boundary as f64 / 1_000_000.0; // Convert microseconds to seconds
            output.push_str(&format!("gquic_latency_seconds_bucket{{le=\"{}\"}} {}\n", boundary_seconds, cumulative));
        }

        output.push_str(&format!("gquic_latency_seconds_bucket{{le=\"+Inf\"}} {}\n", histogram.total_samples.load(Ordering::Relaxed)));
        output.push_str(&format!("gquic_latency_seconds_sum {}\n", histogram.sum_latency_us.load(Ordering::Relaxed) as f64 / 1_000_000.0));
        output.push_str(&format!("gquic_latency_seconds_count {}\n", histogram.total_samples.load(Ordering::Relaxed)));

        output
    }

    /// Start metrics collection background task
    pub fn start_metrics_collection(&self) -> tokio::task::JoinHandle<()> {
        let performance_metrics = Arc::clone(&self.performance_metrics);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));

            loop {
                interval.tick().await;

                // Update performance metrics
                // In a real implementation, these would collect actual system metrics
                let cpu = get_cpu_usage();
                let memory = get_memory_usage();

                performance_metrics.cpu_usage.store((cpu * 100.0) as u64, Ordering::Relaxed);
                performance_metrics.memory_usage.store(memory, Ordering::Relaxed);

                debug!("Updated performance metrics: CPU {:.2}%, Memory {}MB",
                       cpu * 100.0, memory / (1024 * 1024));
            }
        })
    }
}

/// Performance summary for monitoring dashboards
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceSummary {
    pub cpu_usage_percent: f64,
    pub memory_usage_mb: f64,
    pub packets_per_second: u64,
    pub throughput_mbps: f64,
    pub processing_latency_us: f64,
}

/// Latency statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyStats {
    pub average: Option<Duration>,
    pub p50: Option<Duration>,
    pub p95: Option<Duration>,
    pub p99: Option<Duration>,
    pub p999: Option<Duration>,
    pub total_samples: u64,
}

/// Health check status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Warning { message: String },
    Critical { message: String },
}

/// Comprehensive health check
pub async fn health_check(metrics: &MetricsCollector) -> HealthStatus {
    let quic_metrics = metrics.get_quic_metrics().await;
    let performance = metrics.get_performance_summary();

    // Check packet loss rate
    let loss_rate = if quic_metrics.packets_sent > 0 {
        quic_metrics.packets_lost as f64 / quic_metrics.packets_sent as f64
    } else {
        0.0
    };

    if loss_rate > 0.1 {
        return HealthStatus::Critical {
            message: format!("High packet loss rate: {:.2}%", loss_rate * 100.0),
        };
    }

    // Check CPU usage
    if performance.cpu_usage_percent > 90.0 {
        return HealthStatus::Critical {
            message: format!("High CPU usage: {:.1}%", performance.cpu_usage_percent),
        };
    }

    if performance.cpu_usage_percent > 70.0 {
        return HealthStatus::Warning {
            message: format!("Elevated CPU usage: {:.1}%", performance.cpu_usage_percent),
        };
    }

    HealthStatus::Healthy
}

// Helper functions for system metrics (simplified implementations)
fn get_cpu_usage() -> f64 {
    // Placeholder - would use actual system monitoring
    0.15 // 15% CPU usage
}

fn get_memory_usage() -> u64 {
    // Placeholder - would use actual memory monitoring
    256 * 1024 * 1024 // 256MB
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_metrics_collection() {
        let collector = MetricsCollector::new();

        // Record some metrics
        collector.record_packet_sent(1200).await;
        collector.record_packet_received(800).await;
        collector.record_latency(Duration::from_millis(50)).await;

        let metrics = collector.get_quic_metrics().await;
        assert_eq!(metrics.packets_sent, 1);
        assert_eq!(metrics.packets_received, 1);
        assert_eq!(metrics.bytes_sent, 1200);
        assert_eq!(metrics.bytes_received, 800);
    }

    #[tokio::test]
    async fn test_latency_histogram() {
        let collector = MetricsCollector::new();

        // Record various latencies
        collector.record_latency(Duration::from_micros(100)).await;
        collector.record_latency(Duration::from_micros(500)).await;
        collector.record_latency(Duration::from_millis(1)).await;
        collector.record_latency(Duration::from_millis(10)).await;

        let stats = collector.get_latency_stats().await;
        assert_eq!(stats.total_samples, 4);
        assert!(stats.average.is_some());
        assert!(stats.p95.is_some());
    }

    #[tokio::test]
    async fn test_prometheus_export() {
        let collector = MetricsCollector::new();

        collector.record_packet_sent(1000).await;
        collector.record_packet_received(800).await;

        let prometheus_output = collector.export_prometheus().await;
        assert!(prometheus_output.contains("gquic_packets_sent_total 1"));
        assert!(prometheus_output.contains("gquic_packets_received_total 1"));
    }

    #[test]
    fn test_performance_summary() {
        let collector = MetricsCollector::new();

        // Set some performance metrics
        collector.performance_metrics.cpu_usage.store(7500, Ordering::Relaxed); // 75%
        collector.performance_metrics.memory_usage.store(512 * 1024 * 1024, Ordering::Relaxed); // 512MB

        let summary = collector.get_performance_summary();
        assert_eq!(summary.cpu_usage_percent, 75.0);
        assert_eq!(summary.memory_usage_mb, 512.0);
    }

    #[tokio::test]
    async fn test_health_check() {
        let collector = MetricsCollector::new();

        // Healthy state
        let status = health_check(&collector).await;
        assert!(matches!(status, HealthStatus::Healthy));

        // High packet loss
        collector.record_packet_sent(100).await;
        collector.record_packet_loss(20).await; // 20% loss

        let status = health_check(&collector).await;
        assert!(matches!(status, HealthStatus::Critical { .. }));
    }
}