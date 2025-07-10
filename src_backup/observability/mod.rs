use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{event, span, Level, Span};

use crate::quic::{ConnectionId, StreamId};

/// Comprehensive observability system for GQUIC
#[derive(Debug)]
pub struct ObservabilityManager {
    connection_traces: Arc<RwLock<HashMap<ConnectionId, ConnectionTrace>>>,
    global_metrics: Arc<RwLock<GlobalMetrics>>,
}

#[derive(Debug)]
pub struct ConnectionTrace {
    connection_id: ConnectionId,
    start_time: Instant,
    events: Vec<TraceEvent>,
    metrics: ConnectionMetrics,
    span: Span,
}

#[derive(Debug, Clone)]
pub struct TraceEvent {
    timestamp: Instant,
    event_type: EventType,
    details: String,
    level: Level,
}

#[derive(Debug, Clone)]
pub enum EventType {
    ConnectionEstablished,
    PacketSent { size: usize, packet_type: String },
    PacketReceived { size: usize, packet_type: String },
    PacketLost { packet_number: u64 },
    StreamOpened { stream_id: StreamId, direction: String },
    StreamClosed { stream_id: StreamId },
    CryptoHandshake { stage: String },
    FlowControlUpdate { window: u64 },
    CongestionWindowUpdate { size: u64 },
    Error { error: String, severity: String },
    SecurityEvent { event: String, source_ip: String },
}

#[derive(Debug, Default, Clone)]
pub struct ConnectionMetrics {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub packets_lost: u64,
    pub round_trip_time: Option<Duration>,
    pub congestion_window: u64,
    pub streams_opened: u64,
    pub streams_closed: u64,
    pub crypto_handshake_time: Option<Duration>,
}

#[derive(Debug, Default, Clone)]
pub struct GlobalMetrics {
    pub total_connections: u64,
    pub active_connections: u64,
    pub total_bytes_transferred: u64,
    pub average_connection_duration: Duration,
    pub packet_loss_rate: f64,
    pub security_events: u64,
}

impl ObservabilityManager {
    pub fn new() -> Self {
        Self {
            connection_traces: Arc::new(RwLock::new(HashMap::new())),
            global_metrics: Arc::new(RwLock::new(GlobalMetrics::default())),
        }
    }

    /// Start tracing a new connection
    pub async fn start_connection_trace(&self, connection_id: ConnectionId) {
        let span = span!(Level::INFO, "quic_connection", conn_id = %connection_id);
        let _enter = span.enter();
        
        event!(Level::INFO, "Connection trace started");
        
        let trace = ConnectionTrace {
            connection_id: connection_id.clone(),
            start_time: Instant::now(),
            events: Vec::new(),
            metrics: ConnectionMetrics::default(),
            span: span.clone(),
        };
        
        let mut traces = self.connection_traces.write().await;
        traces.insert(connection_id, trace);
        
        // Update global metrics
        let mut global = self.global_metrics.write().await;
        global.total_connections += 1;
        global.active_connections += 1;
    }

    /// Log an event for a connection
    pub async fn log_event(&self, connection_id: &ConnectionId, event_type: EventType, level: Level) {
        let mut traces = self.connection_traces.write().await;
        
        if let Some(trace) = traces.get_mut(connection_id) {
            let _enter = trace.span.enter();
            
            let details = format!("{:?}", event_type);
            match level {
                Level::ERROR => tracing::error!(event = %details),
                Level::WARN => tracing::warn!(event = %details),
                Level::INFO => tracing::info!(event = %details),
                Level::DEBUG => tracing::debug!(event = %details),
                Level::TRACE => tracing::trace!(event = %details),
            }
            
            let trace_event = TraceEvent {
                timestamp: Instant::now(),
                event_type: event_type.clone(),
                details,
                level,
            };
            
            trace.events.push(trace_event);
            
            // Update connection metrics based on event
            self.update_connection_metrics(&mut trace.metrics, &event_type).await;
        }
    }

    /// Update connection metrics
    async fn update_connection_metrics(&self, metrics: &mut ConnectionMetrics, event: &EventType) {
        match event {
            EventType::PacketSent { size, .. } => {
                metrics.packets_sent += 1;
                metrics.bytes_sent += *size as u64;
            }
            EventType::PacketReceived { size, .. } => {
                metrics.packets_received += 1;
                metrics.bytes_received += *size as u64;
            }
            EventType::PacketLost { .. } => {
                metrics.packets_lost += 1;
            }
            EventType::StreamOpened { .. } => {
                metrics.streams_opened += 1;
            }
            EventType::StreamClosed { .. } => {
                metrics.streams_closed += 1;
            }
            EventType::CongestionWindowUpdate { size } => {
                metrics.congestion_window = *size;
            }
            _ => {}
        }
    }

    /// End connection trace
    pub async fn end_connection_trace(&self, connection_id: &ConnectionId) {
        let mut traces = self.connection_traces.write().await;
        
        if let Some(trace) = traces.remove(connection_id) {
            let _enter = trace.span.enter();
            let duration = trace.start_time.elapsed();
            
            event!(Level::INFO, 
                   duration_ms = duration.as_millis(),
                   events_count = trace.events.len(),
                   "Connection trace ended"
            );
            
            // Update global metrics
            let mut global = self.global_metrics.write().await;
            global.active_connections -= 1;
            global.total_bytes_transferred += trace.metrics.bytes_sent + trace.metrics.bytes_received;
            
            // Update average connection duration
            let total_duration = global.average_connection_duration.as_millis() as u64 * (global.total_connections - 1);
            global.average_connection_duration = Duration::from_millis(
                (total_duration + duration.as_millis() as u64) / global.total_connections
            );
            
            // Update packet loss rate
            if trace.metrics.packets_sent > 0 {
                global.packet_loss_rate = trace.metrics.packets_lost as f64 / trace.metrics.packets_sent as f64;
            }
        }
    }

    /// Get connection metrics
    pub async fn get_connection_metrics(&self, connection_id: &ConnectionId) -> Option<ConnectionMetrics> {
        let traces = self.connection_traces.read().await;
        traces.get(connection_id).map(|trace| trace.metrics.clone())
    }

    /// Get global metrics
    pub async fn get_global_metrics(&self) -> GlobalMetrics {
        let global = self.global_metrics.read().await;
        global.clone()
    }

    /// Generate health report
    pub async fn health_report(&self) -> HealthReport {
        let global = self.global_metrics.read().await;
        let traces = self.connection_traces.read().await;
        
        let mut unhealthy_connections = 0;
        let mut high_latency_connections = 0;
        
        for trace in traces.values() {
            if trace.metrics.packets_lost > trace.metrics.packets_sent / 10 {
                unhealthy_connections += 1;
            }
            
            if let Some(rtt) = trace.metrics.round_trip_time {
                if rtt > Duration::from_millis(100) {
                    high_latency_connections += 1;
                }
            }
        }
        
        HealthReport {
            total_connections: global.total_connections,
            active_connections: global.active_connections,
            unhealthy_connections,
            high_latency_connections,
            packet_loss_rate: global.packet_loss_rate,
            average_connection_duration: global.average_connection_duration,
            security_events: global.security_events,
            status: if unhealthy_connections == 0 && global.packet_loss_rate < 0.01 {
                HealthStatus::Healthy
            } else if unhealthy_connections < traces.len() / 10 {
                HealthStatus::Warning
            } else {
                HealthStatus::Critical
            },
        }
    }

    /// Export traces for analysis
    pub async fn export_traces(&self, connection_id: &ConnectionId) -> Option<Vec<TraceEvent>> {
        let traces = self.connection_traces.read().await;
        traces.get(connection_id).map(|trace| trace.events.clone())
    }
}

#[derive(Debug, Clone)]
pub struct HealthReport {
    pub total_connections: u64,
    pub active_connections: u64,
    pub unhealthy_connections: usize,
    pub high_latency_connections: usize,
    pub packet_loss_rate: f64,
    pub average_connection_duration: Duration,
    pub security_events: u64,
    pub status: HealthStatus,
}

#[derive(Debug, Clone, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Warning,
    Critical,
}

/// Integration with structured logging
pub mod structured_logging {
    use super::*;
    use serde_json::json;
    
    pub fn log_crypto_event(
        connection_id: &ConnectionId,
        event_type: &str,
        details: serde_json::Value,
    ) {
        event!(Level::INFO,
            connection_id = %connection_id,
            event_type = event_type,
            details = %details,
            "Crypto event"
        );
    }
    
    pub fn log_performance_metrics(
        connection_id: &ConnectionId,
        metrics: &ConnectionMetrics,
    ) {
        event!(Level::DEBUG,
            connection_id = %connection_id,
            bytes_sent = metrics.bytes_sent,
            bytes_received = metrics.bytes_received,
            packets_lost = metrics.packets_lost,
            rtt_ms = metrics.round_trip_time.map(|d| d.as_millis()),
            congestion_window = metrics.congestion_window,
            "Performance metrics"
        );
    }
    
    pub fn log_security_event(
        source_ip: &str,
        event_type: &str,
        severity: &str,
        details: &str,
    ) {
        event!(Level::WARN,
            source_ip = source_ip,
            event_type = event_type,
            severity = severity,
            details = details,
            "Security event"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_connection_tracing() {
        let obs = ObservabilityManager::new();
        let conn_id = crate::quic::ConnectionId::new();
        
        obs.start_connection_trace(conn_id.clone()).await;
        
        obs.log_event(
            &conn_id,
            EventType::PacketSent { size: 1200, packet_type: "Initial".to_string() },
            Level::DEBUG,
        ).await;
        
        let metrics = obs.get_connection_metrics(&conn_id).await.unwrap();
        assert_eq!(metrics.packets_sent, 1);
        assert_eq!(metrics.bytes_sent, 1200);
        
        obs.end_connection_trace(&conn_id).await;
        
        let global = obs.get_global_metrics().await;
        assert_eq!(global.total_connections, 1);
        assert_eq!(global.active_connections, 0);
    }
}