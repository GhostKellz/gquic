//! Monitoring and observability for QUIC connections
//! 
//! This module provides comprehensive monitoring, metrics collection,
//! and observability features for QUIC connections and servers.

use crate::quic::error::{QuicError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, info, warn, error, instrument};

/// Comprehensive metrics collector for QUIC
#[derive(Debug)]
pub struct QuicMetrics {
    /// Connection metrics
    pub connections: Arc<RwLock<ConnectionMetrics>>,
    /// Stream metrics
    pub streams: Arc<RwLock<StreamMetrics>>,
    /// Packet metrics
    pub packets: Arc<RwLock<PacketMetrics>>,
    /// Error metrics
    pub errors: Arc<RwLock<ErrorMetrics>>,
    /// Performance metrics
    pub performance: Arc<RwLock<PerformanceMetrics>>,
    /// gRPC metrics
    pub grpc: Arc<RwLock<GrpcMetrics>>,
    /// HTTP/3 metrics
    pub http3: Arc<RwLock<Http3Metrics>>,
    /// System metrics
    pub system: Arc<RwLock<SystemMetrics>>,
}

/// Connection-level metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionMetrics {
    /// Total connections opened
    pub total_connections: u64,
    /// Currently active connections
    pub active_connections: u64,
    /// Connections closed gracefully
    pub graceful_closes: u64,
    /// Connections closed due to errors
    pub error_closes: u64,
    /// Connections closed due to timeout
    pub timeout_closes: u64,
    /// Average connection duration
    pub avg_connection_duration: Duration,
    /// Connection establishment times
    pub establishment_times: Vec<Duration>,
    /// Handshake success rate
    pub handshake_success_rate: f64,
    /// Last updated timestamp
    pub last_updated: SystemTime,
}

/// Stream-level metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamMetrics {
    /// Total bidirectional streams opened
    pub total_bi_streams: u64,
    /// Total unidirectional streams opened
    pub total_uni_streams: u64,
    /// Currently active streams
    pub active_streams: u64,
    /// Streams closed successfully
    pub successful_streams: u64,
    /// Streams closed due to errors
    pub error_streams: u64,
    /// Average stream duration
    pub avg_stream_duration: Duration,
    /// Stream data transferred
    pub bytes_sent: u64,
    /// Stream data received
    pub bytes_received: u64,
    /// Stream throughput (bytes/second)
    pub throughput: f64,
    /// Last updated timestamp
    pub last_updated: SystemTime,
}

/// Packet-level metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketMetrics {
    /// Total packets sent
    pub packets_sent: u64,
    /// Total packets received
    pub packets_received: u64,
    /// Packets lost
    pub packets_lost: u64,
    /// Packets retransmitted
    pub packets_retransmitted: u64,
    /// Duplicate packets received
    pub duplicate_packets: u64,
    /// Out-of-order packets
    pub out_of_order_packets: u64,
    /// Average packet size
    pub avg_packet_size: f64,
    /// Packet loss rate
    pub loss_rate: f64,
    /// Round-trip time measurements
    pub rtt_measurements: Vec<Duration>,
    /// Average RTT
    pub avg_rtt: Duration,
    /// Last updated timestamp
    pub last_updated: SystemTime,
}

/// Error metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorMetrics {
    /// Total errors
    pub total_errors: u64,
    /// Connection errors
    pub connection_errors: u64,
    /// Stream errors
    pub stream_errors: u64,
    /// Crypto errors
    pub crypto_errors: u64,
    /// Protocol errors
    pub protocol_errors: u64,
    /// Timeout errors
    pub timeout_errors: u64,
    /// Security errors
    pub security_errors: u64,
    /// Error distribution by type
    pub error_distribution: HashMap<String, u64>,
    /// Last updated timestamp
    pub last_updated: SystemTime,
}

/// Performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// CPU usage percentage
    pub cpu_usage: f64,
    /// Memory usage in bytes
    pub memory_usage: u64,
    /// Network bandwidth utilization
    pub bandwidth_utilization: f64,
    /// Connection pool utilization
    pub pool_utilization: f64,
    /// Average response time
    pub avg_response_time: Duration,
    /// 95th percentile response time
    pub p95_response_time: Duration,
    /// 99th percentile response time
    pub p99_response_time: Duration,
    /// Requests per second
    pub requests_per_second: f64,
    /// Congestion window size
    pub congestion_window: u64,
    /// Flow control window size
    pub flow_control_window: u64,
    /// Last updated timestamp
    pub last_updated: SystemTime,
}

/// gRPC-specific metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrpcMetrics {
    /// Total gRPC requests
    pub total_requests: u64,
    /// Successful gRPC requests
    pub successful_requests: u64,
    /// Failed gRPC requests
    pub failed_requests: u64,
    /// Average request duration
    pub avg_request_duration: Duration,
    /// Request rate (requests/second)
    pub request_rate: f64,
    /// Method call distribution
    pub method_calls: HashMap<String, u64>,
    /// Status code distribution
    pub status_codes: HashMap<u32, u64>,
    /// Message sizes
    pub message_sizes: Vec<u64>,
    /// Average message size
    pub avg_message_size: f64,
    /// Last updated timestamp
    pub last_updated: SystemTime,
}

/// HTTP/3 specific metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Http3Metrics {
    /// Total HTTP/3 requests
    pub total_requests: u64,
    /// Successful HTTP/3 requests
    pub successful_requests: u64,
    /// Failed HTTP/3 requests
    pub failed_requests: u64,
    /// HTTP methods distribution
    pub methods: HashMap<String, u64>,
    /// HTTP status codes distribution
    pub status_codes: HashMap<u16, u64>,
    /// Average request size
    pub avg_request_size: f64,
    /// Average response size
    pub avg_response_size: f64,
    /// Request processing time
    pub avg_processing_time: Duration,
    /// Last updated timestamp
    pub last_updated: SystemTime,
}

/// System-level metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    /// System uptime
    pub uptime: Duration,
    /// File descriptor usage
    pub fd_usage: u64,
    /// Socket usage
    pub socket_usage: u64,
    /// Thread count
    pub thread_count: u64,
    /// Heap memory usage
    pub heap_usage: u64,
    /// Garbage collection metrics
    pub gc_count: u64,
    /// Last updated timestamp
    pub last_updated: SystemTime,
}

impl Default for ConnectionMetrics {
    fn default() -> Self {
        Self {
            total_connections: 0,
            active_connections: 0,
            graceful_closes: 0,
            error_closes: 0,
            timeout_closes: 0,
            avg_connection_duration: Duration::from_secs(0),
            establishment_times: Vec::new(),
            handshake_success_rate: 0.0,
            last_updated: SystemTime::now(),
        }
    }
}

impl Default for StreamMetrics {
    fn default() -> Self {
        Self {
            total_bi_streams: 0,
            total_uni_streams: 0,
            active_streams: 0,
            successful_streams: 0,
            error_streams: 0,
            avg_stream_duration: Duration::from_secs(0),
            bytes_sent: 0,
            bytes_received: 0,
            throughput: 0.0,
            last_updated: SystemTime::now(),
        }
    }
}

impl Default for PacketMetrics {
    fn default() -> Self {
        Self {
            packets_sent: 0,
            packets_received: 0,
            packets_lost: 0,
            packets_retransmitted: 0,
            duplicate_packets: 0,
            out_of_order_packets: 0,
            avg_packet_size: 0.0,
            loss_rate: 0.0,
            rtt_measurements: Vec::new(),
            avg_rtt: Duration::from_secs(0),
            last_updated: SystemTime::now(),
        }
    }
}

impl Default for ErrorMetrics {
    fn default() -> Self {
        Self {
            total_errors: 0,
            connection_errors: 0,
            stream_errors: 0,
            crypto_errors: 0,
            protocol_errors: 0,
            timeout_errors: 0,
            security_errors: 0,
            error_distribution: HashMap::new(),
            last_updated: SystemTime::now(),
        }
    }
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self {
            cpu_usage: 0.0,
            memory_usage: 0,
            bandwidth_utilization: 0.0,
            pool_utilization: 0.0,
            avg_response_time: Duration::from_secs(0),
            p95_response_time: Duration::from_secs(0),
            p99_response_time: Duration::from_secs(0),
            requests_per_second: 0.0,
            congestion_window: 0,
            flow_control_window: 0,
            last_updated: SystemTime::now(),
        }
    }
}

impl Default for GrpcMetrics {
    fn default() -> Self {
        Self {
            total_requests: 0,
            successful_requests: 0,
            failed_requests: 0,
            avg_request_duration: Duration::from_secs(0),
            request_rate: 0.0,
            method_calls: HashMap::new(),
            status_codes: HashMap::new(),
            message_sizes: Vec::new(),
            avg_message_size: 0.0,
            last_updated: SystemTime::now(),
        }
    }
}

impl Default for Http3Metrics {
    fn default() -> Self {
        Self {
            total_requests: 0,
            successful_requests: 0,
            failed_requests: 0,
            methods: HashMap::new(),
            status_codes: HashMap::new(),
            avg_request_size: 0.0,
            avg_response_size: 0.0,
            avg_processing_time: Duration::from_secs(0),
            last_updated: SystemTime::now(),
        }
    }
}

impl Default for SystemMetrics {
    fn default() -> Self {
        Self {
            uptime: Duration::from_secs(0),
            fd_usage: 0,
            socket_usage: 0,
            thread_count: 0,
            heap_usage: 0,
            gc_count: 0,
            last_updated: SystemTime::now(),
        }
    }
}

impl QuicMetrics {
    /// Create a new metrics collector
    pub fn new() -> Self {
        Self {
            connections: Arc::new(RwLock::new(ConnectionMetrics::default())),
            streams: Arc::new(RwLock::new(StreamMetrics::default())),
            packets: Arc::new(RwLock::new(PacketMetrics::default())),
            errors: Arc::new(RwLock::new(ErrorMetrics::default())),
            performance: Arc::new(RwLock::new(PerformanceMetrics::default())),
            grpc: Arc::new(RwLock::new(GrpcMetrics::default())),
            http3: Arc::new(RwLock::new(Http3Metrics::default())),
            system: Arc::new(RwLock::new(SystemMetrics::default())),
        }
    }

    /// Record a new connection
    #[instrument(skip(self))]
    pub async fn record_connection_opened(&self) {
        let mut metrics = self.connections.write().await;
        metrics.total_connections += 1;
        metrics.active_connections += 1;
        metrics.last_updated = SystemTime::now();
        debug!("Connection opened. Total: {}, Active: {}", 
               metrics.total_connections, metrics.active_connections);
    }

    /// Record a connection closed
    #[instrument(skip(self))]
    pub async fn record_connection_closed(&self, reason: ConnectionCloseReason, duration: Duration) {
        let mut metrics = self.connections.write().await;
        metrics.active_connections = metrics.active_connections.saturating_sub(1);
        
        match reason {
            ConnectionCloseReason::Graceful => metrics.graceful_closes += 1,
            ConnectionCloseReason::Error => metrics.error_closes += 1,
            ConnectionCloseReason::Timeout => metrics.timeout_closes += 1,
        }
        
        metrics.establishment_times.push(duration);
        
        // Update average duration
        let total_duration: Duration = metrics.establishment_times.iter().sum();
        metrics.avg_connection_duration = total_duration / metrics.establishment_times.len() as u32;
        
        metrics.last_updated = SystemTime::now();
        debug!("Connection closed ({:?}). Active: {}", reason, metrics.active_connections);
    }

    /// Record stream data
    #[instrument(skip(self))]
    pub async fn record_stream_data(&self, bytes_sent: u64, bytes_received: u64) {
        let mut metrics = self.streams.write().await;
        metrics.bytes_sent += bytes_sent;
        metrics.bytes_received += bytes_received;
        
        // Calculate throughput (simplified)
        let elapsed = metrics.last_updated.elapsed().unwrap_or(Duration::from_secs(1));
        let total_bytes = bytes_sent + bytes_received;
        metrics.throughput = total_bytes as f64 / elapsed.as_secs_f64();
        
        metrics.last_updated = SystemTime::now();
    }

    /// Record packet statistics
    #[instrument(skip(self))]
    pub async fn record_packet_stats(&self, sent: u64, received: u64, lost: u64, rtt: Duration) {
        let mut metrics = self.packets.write().await;
        metrics.packets_sent += sent;
        metrics.packets_received += received;
        metrics.packets_lost += lost;
        
        // Calculate loss rate
        let total_packets = metrics.packets_sent + metrics.packets_received;
        if total_packets > 0 {
            metrics.loss_rate = metrics.packets_lost as f64 / total_packets as f64;
        }
        
        // Update RTT measurements
        metrics.rtt_measurements.push(rtt);
        if metrics.rtt_measurements.len() > 100 {
            metrics.rtt_measurements.drain(0..50); // Keep last 100 measurements
        }
        
        // Calculate average RTT
        let total_rtt: Duration = metrics.rtt_measurements.iter().sum();
        metrics.avg_rtt = total_rtt / metrics.rtt_measurements.len() as u32;
        
        metrics.last_updated = SystemTime::now();
    }

    /// Record an error
    #[instrument(skip(self))]
    pub async fn record_error(&self, error_type: ErrorType, error_message: &str) {
        let mut metrics = self.errors.write().await;
        metrics.total_errors += 1;
        
        match error_type {
            ErrorType::Connection => metrics.connection_errors += 1,
            ErrorType::Stream => metrics.stream_errors += 1,
            ErrorType::Crypto => metrics.crypto_errors += 1,
            ErrorType::Protocol => metrics.protocol_errors += 1,
            ErrorType::Timeout => metrics.timeout_errors += 1,
            ErrorType::Security => metrics.security_errors += 1,
        }
        
        // Update error distribution
        let error_key = format!("{:?}", error_type);
        *metrics.error_distribution.entry(error_key).or_insert(0) += 1;
        
        metrics.last_updated = SystemTime::now();
        warn!("Error recorded: {:?} - {}", error_type, error_message);
    }

    /// Record gRPC request
    #[instrument(skip(self))]
    pub async fn record_grpc_request(&self, method: &str, status_code: u32, duration: Duration, message_size: u64) {
        let mut metrics = self.grpc.write().await;
        metrics.total_requests += 1;
        
        if status_code == 0 {
            metrics.successful_requests += 1;
        } else {
            metrics.failed_requests += 1;
        }
        
        // Update method calls
        *metrics.method_calls.entry(method.to_string()).or_insert(0) += 1;
        
        // Update status codes
        *metrics.status_codes.entry(status_code).or_insert(0) += 1;
        
        // Update message sizes
        metrics.message_sizes.push(message_size);
        if metrics.message_sizes.len() > 1000 {
            metrics.message_sizes.drain(0..500); // Keep last 1000 measurements
        }
        
        // Calculate averages
        let total_size: u64 = metrics.message_sizes.iter().sum();
        metrics.avg_message_size = total_size as f64 / metrics.message_sizes.len() as f64;
        
        metrics.last_updated = SystemTime::now();
    }

    /// Record HTTP/3 request
    #[instrument(skip(self))]
    pub async fn record_http3_request(&self, method: &str, status_code: u16, processing_time: Duration) {
        let mut metrics = self.http3.write().await;
        metrics.total_requests += 1;
        
        if status_code < 400 {
            metrics.successful_requests += 1;
        } else {
            metrics.failed_requests += 1;
        }
        
        // Update method distribution
        *metrics.methods.entry(method.to_string()).or_insert(0) += 1;
        
        // Update status code distribution
        *metrics.status_codes.entry(status_code).or_insert(0) += 1;
        
        metrics.last_updated = SystemTime::now();
    }

    /// Get snapshot of all metrics
    pub async fn get_snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            connections: self.connections.read().await.clone(),
            streams: self.streams.read().await.clone(),
            packets: self.packets.read().await.clone(),
            errors: self.errors.read().await.clone(),
            performance: self.performance.read().await.clone(),
            grpc: self.grpc.read().await.clone(),
            http3: self.http3.read().await.clone(),
            system: self.system.read().await.clone(),
            timestamp: SystemTime::now(),
        }
    }

    /// Export metrics in Prometheus format
    pub async fn export_prometheus(&self) -> String {
        let snapshot = self.get_snapshot().await;
        let mut output = String::new();
        
        // Connection metrics
        output.push_str(&format!("# HELP quic_connections_total Total number of connections\n"));
        output.push_str(&format!("# TYPE quic_connections_total counter\n"));
        output.push_str(&format!("quic_connections_total {}\n", snapshot.connections.total_connections));
        
        output.push_str(&format!("# HELP quic_connections_active Currently active connections\n"));
        output.push_str(&format!("# TYPE quic_connections_active gauge\n"));
        output.push_str(&format!("quic_connections_active {}\n", snapshot.connections.active_connections));
        
        // Stream metrics
        output.push_str(&format!("# HELP quic_streams_total Total number of streams\n"));
        output.push_str(&format!("# TYPE quic_streams_total counter\n"));
        output.push_str(&format!("quic_streams_total{{type=\"bidirectional\"}} {}\n", snapshot.streams.total_bi_streams));
        output.push_str(&format!("quic_streams_total{{type=\"unidirectional\"}} {}\n", snapshot.streams.total_uni_streams));
        
        // Packet metrics
        output.push_str(&format!("# HELP quic_packets_total Total number of packets\n"));
        output.push_str(&format!("# TYPE quic_packets_total counter\n"));
        output.push_str(&format!("quic_packets_total{{direction=\"sent\"}} {}\n", snapshot.packets.packets_sent));
        output.push_str(&format!("quic_packets_total{{direction=\"received\"}} {}\n", snapshot.packets.packets_received));
        output.push_str(&format!("quic_packets_total{{direction=\"lost\"}} {}\n", snapshot.packets.packets_lost));
        
        // Error metrics
        output.push_str(&format!("# HELP quic_errors_total Total number of errors\n"));
        output.push_str(&format!("# TYPE quic_errors_total counter\n"));
        output.push_str(&format!("quic_errors_total {}\n", snapshot.errors.total_errors));
        
        // gRPC metrics
        output.push_str(&format!("# HELP grpc_requests_total Total number of gRPC requests\n"));
        output.push_str(&format!("# TYPE grpc_requests_total counter\n"));
        output.push_str(&format!("grpc_requests_total {}\n", snapshot.grpc.total_requests));
        
        output
    }
}

/// Connection close reason
#[derive(Debug, Clone, Copy)]
pub enum ConnectionCloseReason {
    Graceful,
    Error,
    Timeout,
}

/// Error type categorization
#[derive(Debug, Clone, Copy)]
pub enum ErrorType {
    Connection,
    Stream,
    Crypto,
    Protocol,
    Timeout,
    Security,
}

/// Complete metrics snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub connections: ConnectionMetrics,
    pub streams: StreamMetrics,
    pub packets: PacketMetrics,
    pub errors: ErrorMetrics,
    pub performance: PerformanceMetrics,
    pub grpc: GrpcMetrics,
    pub http3: Http3Metrics,
    pub system: SystemMetrics,
    pub timestamp: SystemTime,
}

/// Metrics exporter trait
pub trait MetricsExporter {
    /// Export metrics to external system
    fn export(&self, snapshot: &MetricsSnapshot) -> Result<()>;
}

/// Health check status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub status: HealthState,
    pub checks: Vec<HealthCheck>,
    pub timestamp: SystemTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HealthState {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    pub name: String,
    pub status: HealthState,
    pub message: String,
    pub duration: Duration,
}

/// Health checker
pub struct HealthChecker {
    metrics: Arc<QuicMetrics>,
    checks: Vec<Box<dyn Fn(&MetricsSnapshot) -> HealthCheck + Send + Sync>>,
}

impl HealthChecker {
    pub fn new(metrics: Arc<QuicMetrics>) -> Self {
        Self {
            metrics,
            checks: Vec::new(),
        }
    }
    
    pub fn add_check<F>(&mut self, check: F) 
    where 
        F: Fn(&MetricsSnapshot) -> HealthCheck + Send + Sync + 'static 
    {
        self.checks.push(Box::new(check));
    }
    
    pub async fn check_health(&self) -> HealthStatus {
        let snapshot = self.metrics.get_snapshot().await;
        let mut checks = Vec::new();
        let mut overall_status = HealthState::Healthy;
        
        for check_fn in &self.checks {
            let check_result = check_fn(&snapshot);
            
            match check_result.status {
                HealthState::Degraded => {
                    if matches!(overall_status, HealthState::Healthy) {
                        overall_status = HealthState::Degraded;
                    }
                }
                HealthState::Unhealthy => {
                    overall_status = HealthState::Unhealthy;
                }
                _ => {}
            }
            
            checks.push(check_result);
        }
        
        HealthStatus {
            status: overall_status,
            checks,
            timestamp: SystemTime::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_metrics_collection() {
        let metrics = QuicMetrics::new();
        
        // Record some metrics
        metrics.record_connection_opened().await;
        metrics.record_stream_data(1024, 2048).await;
        metrics.record_error(ErrorType::Connection, "Test error").await;
        
        let snapshot = metrics.get_snapshot().await;
        
        assert_eq!(snapshot.connections.total_connections, 1);
        assert_eq!(snapshot.connections.active_connections, 1);
        assert_eq!(snapshot.streams.bytes_sent, 1024);
        assert_eq!(snapshot.streams.bytes_received, 2048);
        assert_eq!(snapshot.errors.total_errors, 1);
        assert_eq!(snapshot.errors.connection_errors, 1);
    }
    
    #[tokio::test]
    async fn test_prometheus_export() {
        let metrics = QuicMetrics::new();
        metrics.record_connection_opened().await;
        
        let prometheus_output = metrics.export_prometheus().await;
        
        assert!(prometheus_output.contains("quic_connections_total 1"));
        assert!(prometheus_output.contains("quic_connections_active 1"));
    }
    
    #[tokio::test]
    async fn test_health_checker() {
        let metrics = Arc::new(QuicMetrics::new());
        let mut health_checker = HealthChecker::new(metrics.clone());
        
        // Add a simple health check
        health_checker.add_check(|snapshot| {
            HealthCheck {
                name: "connection_count".to_string(),
                status: if snapshot.connections.active_connections < 1000 {
                    HealthState::Healthy
                } else {
                    HealthState::Degraded
                },
                message: format!("Active connections: {}", snapshot.connections.active_connections),
                duration: Duration::from_millis(1),
            }
        });
        
        let health_status = health_checker.check_health().await;
        assert!(matches!(health_status.status, HealthState::Healthy));
        assert_eq!(health_status.checks.len(), 1);
    }
}