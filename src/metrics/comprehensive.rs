use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Mutex};
use serde::{Serialize, Deserialize};
use tracing::{debug, info, warn};

use crate::quic::{ConnectionId, StreamId};

/// Comprehensive metrics collection and health monitoring system
#[derive(Debug)]
pub struct MetricsCollector {
    /// Connection-level metrics
    connection_metrics: Arc<RwLock<HashMap<ConnectionId, ConnectionMetrics>>>,
    /// Global aggregate metrics
    global_metrics: Arc<RwLock<GlobalMetrics>>,
    /// Performance histograms
    histograms: Arc<RwLock<MetricsHistograms>>,
    /// Health status tracker
    health_monitor: Arc<Mutex<HealthMonitor>>,
    /// Metrics configuration
    config: MetricsConfig,
}

#[derive(Debug, Clone)]
pub struct MetricsConfig {
    /// Enable detailed per-connection metrics
    pub enable_connection_metrics: bool,
    /// Enable performance histograms
    pub enable_histograms: bool,
    /// Maximum number of connections to track
    pub max_tracked_connections: usize,
    /// Metrics retention period
    pub retention_period: Duration,
    /// Health check interval
    pub health_check_interval: Duration,
    /// Export interval for metrics
    pub export_interval: Duration,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enable_connection_metrics: true,
            enable_histograms: true,
            max_tracked_connections: 10000,
            retention_period: Duration::from_secs(3600), // 1 hour
            health_check_interval: Duration::from_secs(30),
            export_interval: Duration::from_secs(60),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionMetrics {
    pub connection_id: String,
    pub start_time: Instant,
    pub last_activity: Instant,
    
    // Traffic metrics
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub packets_lost: u64,
    pub packets_retransmitted: u64,
    
    // Timing metrics
    pub handshake_duration: Option<Duration>,
    pub min_rtt: Option<Duration>,
    pub max_rtt: Option<Duration>,
    pub avg_rtt: Option<Duration>,
    pub current_rtt: Option<Duration>,
    
    // Stream metrics
    pub streams_opened: u64,
    pub streams_closed: u64,
    pub streams_reset: u64,
    pub max_concurrent_streams: u64,
    
    // Flow control metrics
    pub congestion_window: u64,
    pub receive_window: u64,
    pub flow_control_blocked_count: u64,
    
    // Error metrics
    pub connection_errors: u64,
    pub stream_errors: u64,
    pub crypto_errors: u64,
    pub protocol_errors: u64,
    
    // Quality metrics
    pub packet_loss_rate: f64,
    pub throughput_mbps: f64,
    pub connection_quality_score: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalMetrics {
    pub start_time: Instant,
    pub last_update: Instant,
    
    // Connection metrics
    pub total_connections: u64,
    pub active_connections: u64,
    pub failed_connections: u64,
    pub connections_per_second: f64,
    
    // Traffic metrics
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub total_packets_sent: u64,
    pub total_packets_received: u64,
    pub total_packets_lost: u64,
    
    // Performance metrics
    pub avg_connection_duration: Duration,
    pub avg_handshake_time: Duration,
    pub avg_rtt: Duration,
    pub global_packet_loss_rate: f64,
    pub global_throughput_mbps: f64,
    
    // Resource usage
    pub memory_usage_mb: f64,
    pub cpu_usage_percent: f64,
    pub file_descriptors_used: u64,
    
    // Error rates
    pub error_rate_per_minute: f64,
    pub security_events_per_hour: f64,
    
    // Quality of service
    pub service_availability: f64, // 0.0 - 1.0
    pub average_quality_score: f64,
}

#[derive(Debug)]
struct MetricsHistograms {
    rtt_histogram: Histogram,
    throughput_histogram: Histogram,
    connection_duration_histogram: Histogram,
    handshake_time_histogram: Histogram,
    packet_size_histogram: Histogram,
}

#[derive(Debug)]
struct Histogram {
    buckets: Vec<HistogramBucket>,
    total_count: u64,
    total_sum: f64,
}

#[derive(Debug)]
struct HistogramBucket {
    upper_bound: f64,
    count: u64,
}

#[derive(Debug)]
struct HealthMonitor {
    current_status: HealthStatus,
    status_history: VecDeque<HealthStatusEvent>,
    alerts: Vec<Alert>,
    last_health_check: Instant,
    uptime_start: Instant,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Warning,
    Critical,
    Down,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatusEvent {
    pub timestamp: Instant,
    pub status: HealthStatus,
    pub reason: String,
    pub metrics_snapshot: HealthMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub level: AlertLevel,
    pub message: String,
    pub timestamp: Instant,
    pub resolved: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AlertLevel {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthMetrics {
    pub packet_loss_rate: f64,
    pub avg_rtt_ms: f64,
    pub connection_success_rate: f64,
    pub error_rate: f64,
    pub throughput_mbps: f64,
    pub active_connections: u64,
    pub memory_usage_mb: f64,
    pub cpu_usage_percent: f64,
}

impl MetricsCollector {
    pub fn new(config: MetricsConfig) -> Self {
        let now = Instant::now();
        
        Self {
            connection_metrics: Arc::new(RwLock::new(HashMap::new())),
            global_metrics: Arc::new(RwLock::new(GlobalMetrics {
                start_time: now,
                last_update: now,
                total_connections: 0,
                active_connections: 0,
                failed_connections: 0,
                connections_per_second: 0.0,
                total_bytes_sent: 0,
                total_bytes_received: 0,
                total_packets_sent: 0,
                total_packets_received: 0,
                total_packets_lost: 0,
                avg_connection_duration: Duration::from_millis(0),
                avg_handshake_time: Duration::from_millis(0),
                avg_rtt: Duration::from_millis(0),
                global_packet_loss_rate: 0.0,
                global_throughput_mbps: 0.0,
                memory_usage_mb: 0.0,
                cpu_usage_percent: 0.0,
                file_descriptors_used: 0,
                error_rate_per_minute: 0.0,
                security_events_per_hour: 0.0,
                service_availability: 1.0,
                average_quality_score: 100.0,
            })),
            histograms: Arc::new(RwLock::new(MetricsHistograms::new())),
            health_monitor: Arc::new(Mutex::new(HealthMonitor {
                current_status: HealthStatus::Healthy,
                status_history: VecDeque::new(),
                alerts: Vec::new(),
                last_health_check: now,
                uptime_start: now,
            })),
            config,
        }
    }

    /// Record new connection establishment
    pub async fn record_connection_established(&self, connection_id: ConnectionId, handshake_duration: Option<Duration>) {
        let now = Instant::now();
        
        if self.config.enable_connection_metrics {
            let mut conn_metrics = self.connection_metrics.write().await;
            
            // Remove old connections if at limit
            if conn_metrics.len() >= self.config.max_tracked_connections {
                let oldest_key = conn_metrics.iter()
                    .min_by_key(|(_, metrics)| metrics.last_activity)
                    .map(|(id, _)| id.clone());
                
                if let Some(key) = oldest_key {
                    conn_metrics.remove(&key);
                }
            }
            
            let metrics = ConnectionMetrics {
                connection_id: connection_id.to_string(),
                start_time: now,
                last_activity: now,
                bytes_sent: 0,
                bytes_received: 0,
                packets_sent: 0,
                packets_received: 0,
                packets_lost: 0,
                packets_retransmitted: 0,
                handshake_duration,
                min_rtt: None,
                max_rtt: None,
                avg_rtt: None,
                current_rtt: None,
                streams_opened: 0,
                streams_closed: 0,
                streams_reset: 0,
                max_concurrent_streams: 0,
                congestion_window: 0,
                receive_window: 0,
                flow_control_blocked_count: 0,
                connection_errors: 0,
                stream_errors: 0,
                crypto_errors: 0,
                protocol_errors: 0,
                packet_loss_rate: 0.0,
                throughput_mbps: 0.0,
                connection_quality_score: 100,
            };
            
            conn_metrics.insert(connection_id, metrics);
        }
        
        // Update global metrics
        let mut global = self.global_metrics.write().await;
        global.total_connections += 1;
        global.active_connections += 1;
        global.last_update = now;
        
        if let Some(duration) = handshake_duration {
            if self.config.enable_histograms {
                let mut histograms = self.histograms.write().await;
                histograms.handshake_time_histogram.record(duration.as_millis() as f64);
            }
        }
        
        debug!("Recorded connection establishment for {}", connection_id);
    }

    /// Record connection closure
    pub async fn record_connection_closed(&self, connection_id: &ConnectionId) {
        let now = Instant::now();
        
        if let Some(metrics) = self.get_connection_metrics(connection_id).await {
            let duration = now.duration_since(metrics.start_time);
            
            // Update global averages
            let mut global = self.global_metrics.write().await;
            global.active_connections = global.active_connections.saturating_sub(1);
            
            // Update average connection duration
            let total_duration = global.avg_connection_duration.as_millis() as u64 * (global.total_connections - 1);
            global.avg_connection_duration = Duration::from_millis(
                (total_duration + duration.as_millis() as u64) / global.total_connections
            );
            
            if self.config.enable_histograms {
                let mut histograms = self.histograms.write().await;
                histograms.connection_duration_histogram.record(duration.as_millis() as f64);
            }
        }
        
        // Remove from active tracking
        if self.config.enable_connection_metrics {
            let mut conn_metrics = self.connection_metrics.write().await;
            conn_metrics.remove(connection_id);
        }
        
        debug!("Recorded connection closure for {}", connection_id);
    }

    /// Record packet sent
    pub async fn record_packet_sent(&self, connection_id: &ConnectionId, size: usize) {
        if let Some(mut metrics) = self.get_connection_metrics_mut(connection_id).await {
            metrics.packets_sent += 1;
            metrics.bytes_sent += size as u64;
            metrics.last_activity = Instant::now();
        }
        
        let mut global = self.global_metrics.write().await;
        global.total_packets_sent += 1;
        global.total_bytes_sent += size as u64;
        
        if self.config.enable_histograms {
            let mut histograms = self.histograms.write().await;
            histograms.packet_size_histogram.record(size as f64);
        }
    }

    /// Record packet received
    pub async fn record_packet_received(&self, connection_id: &ConnectionId, size: usize) {
        if let Some(mut metrics) = self.get_connection_metrics_mut(connection_id).await {
            metrics.packets_received += 1;
            metrics.bytes_received += size as u64;
            metrics.last_activity = Instant::now();
        }
        
        let mut global = self.global_metrics.write().await;
        global.total_packets_received += 1;
        global.total_bytes_received += size as u64;
    }

    /// Record packet loss
    pub async fn record_packet_lost(&self, connection_id: &ConnectionId) {
        if let Some(mut metrics) = self.get_connection_metrics_mut(connection_id).await {
            metrics.packets_lost += 1;
            
            // Update packet loss rate
            if metrics.packets_sent > 0 {
                metrics.packet_loss_rate = metrics.packets_lost as f64 / metrics.packets_sent as f64;
            }
        }
        
        let mut global = self.global_metrics.write().await;
        global.total_packets_lost += 1;
        
        // Update global packet loss rate
        if global.total_packets_sent > 0 {
            global.global_packet_loss_rate = global.total_packets_lost as f64 / global.total_packets_sent as f64;
        }
    }

    /// Record RTT measurement
    pub async fn record_rtt(&self, connection_id: &ConnectionId, rtt: Duration) {
        if let Some(mut metrics) = self.get_connection_metrics_mut(connection_id).await {
            metrics.current_rtt = Some(rtt);
            
            // Update min/max RTT
            if metrics.min_rtt.is_none() || rtt < metrics.min_rtt.unwrap() {
                metrics.min_rtt = Some(rtt);
            }
            if metrics.max_rtt.is_none() || rtt > metrics.max_rtt.unwrap() {
                metrics.max_rtt = Some(rtt);
            }
            
            // Update average RTT (simple moving average)
            if let Some(avg_rtt) = metrics.avg_rtt {
                metrics.avg_rtt = Some(Duration::from_nanos(
                    (avg_rtt.as_nanos() as u64 * 7 + rtt.as_nanos() as u64) / 8
                ));
            } else {
                metrics.avg_rtt = Some(rtt);
            }
        }
        
        if self.config.enable_histograms {
            let mut histograms = self.histograms.write().await;
            histograms.rtt_histogram.record(rtt.as_millis() as f64);
        }
    }

    /// Record stream opened
    pub async fn record_stream_opened(&self, connection_id: &ConnectionId, _stream_id: StreamId) {
        if let Some(mut metrics) = self.get_connection_metrics_mut(connection_id).await {
            metrics.streams_opened += 1;
            let current_streams = metrics.streams_opened - metrics.streams_closed;
            if current_streams > metrics.max_concurrent_streams {
                metrics.max_concurrent_streams = current_streams;
            }
        }
    }

    /// Record stream closed
    pub async fn record_stream_closed(&self, connection_id: &ConnectionId, _stream_id: StreamId) {
        if let Some(mut metrics) = self.get_connection_metrics_mut(connection_id).await {
            metrics.streams_closed += 1;
        }
    }

    /// Record error
    pub async fn record_error(&self, connection_id: &ConnectionId, error_type: ErrorType) {
        if let Some(mut metrics) = self.get_connection_metrics_mut(connection_id).await {
            match error_type {
                ErrorType::Connection => metrics.connection_errors += 1,
                ErrorType::Stream => metrics.stream_errors += 1,
                ErrorType::Crypto => metrics.crypto_errors += 1,
                ErrorType::Protocol => metrics.protocol_errors += 1,
            }
        }
        
        // Update global error rate
        let mut global = self.global_metrics.write().await;
        global.error_rate_per_minute += 1.0 / 60.0; // Simplified calculation
    }

    /// Perform health check
    pub async fn perform_health_check(&self) -> HealthStatus {
        let mut health_monitor = self.health_monitor.lock().await;
        let now = Instant::now();
        
        if now.duration_since(health_monitor.last_health_check) < self.config.health_check_interval {
            return health_monitor.current_status.clone();
        }
        
        let global = self.global_metrics.read().await;
        let health_metrics = HealthMetrics {
            packet_loss_rate: global.global_packet_loss_rate,
            avg_rtt_ms: global.avg_rtt.as_millis() as f64,
            connection_success_rate: if global.total_connections > 0 {
                1.0 - (global.failed_connections as f64 / global.total_connections as f64)
            } else { 1.0 },
            error_rate: global.error_rate_per_minute,
            throughput_mbps: global.global_throughput_mbps,
            active_connections: global.active_connections,
            memory_usage_mb: global.memory_usage_mb,
            cpu_usage_percent: global.cpu_usage_percent,
        };
        
        // Determine health status
        let new_status = self.calculate_health_status(&health_metrics);
        
        // Record status change if different
        if new_status != health_monitor.current_status {
            let event = HealthStatusEvent {
                timestamp: now,
                status: new_status.clone(),
                reason: self.get_health_status_reason(&health_metrics, &new_status),
                metrics_snapshot: health_metrics.clone(),
            };
            
            health_monitor.status_history.push_back(event);
            
            // Keep only recent history
            while health_monitor.status_history.len() > 100 {
                health_monitor.status_history.pop_front();
            }
            
            health_monitor.current_status = new_status.clone();
            
            info!("Health status changed to {:?}", new_status);
        }
        
        health_monitor.last_health_check = now;
        new_status
    }

    /// Calculate health status based on metrics
    fn calculate_health_status(&self, metrics: &HealthMetrics) -> HealthStatus {
        // Critical conditions
        if metrics.packet_loss_rate > 0.1 || // >10% packet loss
           metrics.error_rate > 100.0 || // >100 errors per minute
           metrics.connection_success_rate < 0.5 { // <50% connection success
            return HealthStatus::Critical;
        }
        
        // Warning conditions
        if metrics.packet_loss_rate > 0.05 || // >5% packet loss
           metrics.avg_rtt_ms > 500.0 || // >500ms RTT
           metrics.error_rate > 10.0 || // >10 errors per minute
           metrics.cpu_usage_percent > 80.0 || // >80% CPU
           metrics.memory_usage_mb > 1000.0 { // >1GB memory
            return HealthStatus::Warning;
        }
        
        HealthStatus::Healthy
    }

    /// Get reason for health status
    fn get_health_status_reason(&self, metrics: &HealthMetrics, status: &HealthStatus) -> String {
        match status {
            HealthStatus::Critical => {
                if metrics.packet_loss_rate > 0.1 {
                    format!("High packet loss: {:.1}%", metrics.packet_loss_rate * 100.0)
                } else if metrics.error_rate > 100.0 {
                    format!("High error rate: {:.1}/min", metrics.error_rate)
                } else {
                    format!("Low connection success rate: {:.1}%", metrics.connection_success_rate * 100.0)
                }
            }
            HealthStatus::Warning => {
                if metrics.packet_loss_rate > 0.05 {
                    format!("Elevated packet loss: {:.1}%", metrics.packet_loss_rate * 100.0)
                } else if metrics.avg_rtt_ms > 500.0 {
                    format!("High latency: {:.1}ms", metrics.avg_rtt_ms)
                } else {
                    "Performance degradation detected".to_string()
                }
            }
            _ => "System operating normally".to_string(),
        }
    }

    /// Get connection metrics (read-only)
    async fn get_connection_metrics(&self, connection_id: &ConnectionId) -> Option<ConnectionMetrics> {
        let conn_metrics = self.connection_metrics.read().await;
        conn_metrics.get(connection_id).cloned()
    }

    /// Get connection metrics (mutable)
    async fn get_connection_metrics_mut(&self, connection_id: &ConnectionId) -> Option<ConnectionMetrics> {
        let conn_metrics = self.connection_metrics.read().await;
        conn_metrics.get(connection_id).cloned()
    }

    /// Get global metrics
    pub async fn get_global_metrics(&self) -> GlobalMetrics {
        self.global_metrics.read().await.clone()
    }

    /// Get health report
    pub async fn get_health_report(&self) -> HealthReport {
        let health_monitor = self.health_monitor.lock().await;
        let global = self.global_metrics.read().await;
        
        HealthReport {
            status: health_monitor.current_status.clone(),
            uptime: health_monitor.uptime_start.elapsed(),
            total_connections: global.total_connections,
            active_connections: global.active_connections,
            packet_loss_rate: global.global_packet_loss_rate,
            avg_rtt: global.avg_rtt,
            throughput_mbps: global.global_throughput_mbps,
            error_rate: global.error_rate_per_minute,
            alerts: health_monitor.alerts.clone(),
        }
    }

    /// Export metrics in Prometheus format
    pub async fn export_prometheus(&self) -> String {
        let global = self.global_metrics.read().await;
        let mut output = String::new();
        
        // Global metrics
        output.push_str(&format!("gquic_total_connections {}\n", global.total_connections));
        output.push_str(&format!("gquic_active_connections {}\n", global.active_connections));
        output.push_str(&format!("gquic_total_bytes_sent {}\n", global.total_bytes_sent));
        output.push_str(&format!("gquic_total_bytes_received {}\n", global.total_bytes_received));
        output.push_str(&format!("gquic_packet_loss_rate {}\n", global.global_packet_loss_rate));
        output.push_str(&format!("gquic_avg_rtt_seconds {}\n", global.avg_rtt.as_secs_f64()));
        output.push_str(&format!("gquic_throughput_mbps {}\n", global.global_throughput_mbps));
        
        output
    }
}

#[derive(Debug, Clone)]
pub enum ErrorType {
    Connection,
    Stream,
    Crypto,
    Protocol,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthReport {
    pub status: HealthStatus,
    pub uptime: Duration,
    pub total_connections: u64,
    pub active_connections: u64,
    pub packet_loss_rate: f64,
    pub avg_rtt: Duration,
    pub throughput_mbps: f64,
    pub error_rate: f64,
    pub alerts: Vec<Alert>,
}

impl MetricsHistograms {
    fn new() -> Self {
        Self {
            rtt_histogram: Histogram::new(vec![1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0]),
            throughput_histogram: Histogram::new(vec![1.0, 10.0, 50.0, 100.0, 500.0, 1000.0, 5000.0]),
            connection_duration_histogram: Histogram::new(vec![1.0, 5.0, 30.0, 60.0, 300.0, 1800.0, 3600.0]),
            handshake_time_histogram: Histogram::new(vec![10.0, 50.0, 100.0, 200.0, 500.0, 1000.0]),
            packet_size_histogram: Histogram::new(vec![64.0, 256.0, 512.0, 1024.0, 1200.0, 1500.0, 9000.0]),
        }
    }
}

impl Histogram {
    fn new(bucket_bounds: Vec<f64>) -> Self {
        let buckets = bucket_bounds.into_iter()
            .map(|upper_bound| HistogramBucket { upper_bound, count: 0 })
            .collect();
        
        Self {
            buckets,
            total_count: 0,
            total_sum: 0.0,
        }
    }
    
    fn record(&mut self, value: f64) {
        self.total_count += 1;
        self.total_sum += value;
        
        for bucket in &mut self.buckets {
            if value <= bucket.upper_bound {
                bucket.count += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_metrics_collection() {
        let collector = MetricsCollector::new(MetricsConfig::default());
        let conn_id = crate::quic::ConnectionId::new();
        
        // Record connection establishment
        collector.record_connection_established(conn_id.clone(), Some(Duration::from_millis(100))).await;
        
        // Record some activity
        collector.record_packet_sent(&conn_id, 1200).await;
        collector.record_packet_received(&conn_id, 800).await;
        collector.record_rtt(&conn_id, Duration::from_millis(50)).await;
        
        let global = collector.get_global_metrics().await;
        assert_eq!(global.active_connections, 1);
        assert_eq!(global.total_bytes_sent, 1200);
        assert_eq!(global.total_bytes_received, 800);
    }

    #[tokio::test]
    async fn test_health_monitoring() {
        let collector = MetricsCollector::new(MetricsConfig::default());
        
        let status = collector.perform_health_check().await;
        assert_eq!(status, HealthStatus::Healthy);
        
        let report = collector.get_health_report().await;
        assert_eq!(report.status, HealthStatus::Healthy);
    }
}