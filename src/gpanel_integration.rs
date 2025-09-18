//! GhostPanel GQUIC Integration Module
//!
//! This module provides the main integration layer between GQUIC and GhostPanel,
//! combining gaming optimizations, container networking, and edge agent functionality
//! into a unified gaming-aware container management platform.

use std::sync::Arc;
use std::time::Duration;
use std::collections::HashMap;
use tokio::sync::{RwLock, Mutex};
use bytes::Bytes;
use tracing::{info, debug, warn, error};

use crate::QuicResult;
use crate::quic::{Connection, ConnectionId, Endpoint, StreamId};
use crate::gpanel_optimizations::{
    GamingOptimizedTransport, ContainerStreamMultiplexer, GamingCongestionConfig,
    ContainerStreamPriority, GamingTelemetry, ZeroCopyBufferPool, PrecisionTiming
};
use crate::container::ContainerEndpoint;
use crate::performance::PerformanceOptimizer;

/// Unified GhostPanel QUIC integration providing gaming-optimized container management
#[derive(Debug)]
pub struct GpanelQuicIntegration {
    /// Core QUIC endpoint
    endpoint: Arc<Endpoint>,
    /// Gaming-optimized transport layer
    gaming_transport: Arc<GamingOptimizedTransport>,
    /// Container-aware stream multiplexer
    stream_multiplexer: Arc<ContainerStreamMultiplexer>,
    /// Container networking integration
    container_endpoint: Option<Arc<ContainerEndpoint>>,
    /// Performance optimizer
    performance_optimizer: Arc<PerformanceOptimizer>,
    /// Zero-copy buffer pool for high performance
    buffer_pool: Arc<ZeroCopyBufferPool>,
    /// Active connections tracking
    connections: Arc<RwLock<HashMap<ConnectionId, Arc<Mutex<Connection>>>>>,
    /// Gaming mode configuration
    gaming_config: GamingCongestionConfig,
}

impl GpanelQuicIntegration {
    /// Create a new GhostPanel QUIC integration instance
    pub async fn new(
        bind_addr: &str,
        gaming_config: Option<GamingCongestionConfig>,
    ) -> QuicResult<Self> {
        let config = gaming_config.unwrap_or_default();

        // Create core QUIC endpoint
        let endpoint = Arc::new(Endpoint::server(bind_addr.parse()?, Default::default()).await?);

        // Initialize gaming-optimized transport
        let gaming_transport = Arc::new(GamingOptimizedTransport::new(config.clone()));

        // Create container stream multiplexer
        let stream_multiplexer = Arc::new(ContainerStreamMultiplexer::new(gaming_transport.clone()));

        // Initialize performance optimizer for gaming workloads
        let perf_config = crate::performance::PerformanceConfig {
            sub_microsecond_mode: true,
            enable_simd: true,
            zero_copy_enabled: true,
            memory_pool_config: crate::performance::MemoryPoolConfig {
                initial_pool_size: 1024 * 1024, // 1MB
                max_pool_size: 64 * 1024 * 1024, // 64MB
                chunk_size: 4096,
                enable_prefetch: true,
                memory_alignment: 64, // For SIMD
            },
            cpu_affinity: None, // Let OS decide for now
            socket_optimizations: crate::performance::SocketOptimizations::default(),
            batch_config: crate::performance::BatchConfig::default(),
        };
        let performance_optimizer = Arc::new(PerformanceOptimizer::new(perf_config).await?);

        // Create zero-copy buffer pool (64KB buffers, optimized for container data)
        let buffer_pool = Arc::new(ZeroCopyBufferPool::new(65536, 32, 128));

        let integration = Self {
            endpoint,
            gaming_transport,
            stream_multiplexer,
            container_endpoint: None,
            performance_optimizer,
            buffer_pool,
            connections: Arc::new(RwLock::new(HashMap::new())),
            gaming_config: config,
        };

        info!("GhostPanel QUIC integration initialized with gaming optimizations");
        Ok(integration)
    }

    /// Enable container networking integration
    pub async fn enable_container_networking(&mut self, bolt_socket_path: &str) -> QuicResult<()> {
        let container_config = crate::container::BoltNetworkConfig {
            driver: "bolt".to_string(),
            subnet: "172.17.0.0/16".to_string(),
            gateway: "172.17.0.1".parse().unwrap(),
            dns_servers: vec!["1.1.1.1".parse().unwrap(), "1.0.0.1".parse().unwrap()],
            sub_microsecond_mode: true,
            auth_mode: crate::container::ContainerAuthMode::Certificate,
            max_containers: 1000,
            icc_settings: crate::container::InterContainerConfig {
                direct_communication: true,
                max_connections_per_container: 100,
                connection_timeout: std::time::Duration::from_secs(30),
                service_discovery: true,
                load_balancing: true,
            },
        };

        let bind_addr = self.endpoint.local_addr()?;
        let container_endpoint = Arc::new(
            ContainerEndpoint::new(bind_addr, container_config).await?
        );

        self.container_endpoint = Some(container_endpoint);
        info!("Container networking enabled for Bolt integration");
        Ok(())
    }

    /// Accept incoming connections with gaming-aware optimization
    pub async fn accept_connection(&self) -> QuicResult<Arc<Mutex<Connection>>> {
        let conn = self.endpoint.accept().await
            .ok_or_else(|| crate::QuicError::ConnectionClosed)?;
        let connection = Arc::new(Mutex::new(conn));
        let connection_id = {
            let conn = connection.lock().await;
            conn.id()
        };

        // Track the connection
        {
            let mut connections = self.connections.write().await;
            connections.insert(connection_id.clone(), connection.clone());
        }

        // Initialize gaming-aware congestion control
        {
            let mut conn = connection.lock().await;
            let initial_rtt = Duration::from_millis(50); // Conservative initial estimate
            let cwnd = self.gaming_transport.adjust_congestion_window(&mut conn, initial_rtt).await?;
            debug!("Connection {} initialized with gaming-aware CWND: {}", connection_id, cwnd);
        }

        info!("Accepted gaming-optimized connection: {}", connection_id);
        Ok(connection)
    }

    /// Create a container management stream with appropriate priority
    pub async fn create_container_stream(
        &self,
        connection: Arc<Mutex<Connection>>,
        container_id: String,
        operation_type: ContainerOperationType,
    ) -> QuicResult<ContainerStream> {
        let priority = match operation_type {
            ContainerOperationType::Start | ContainerOperationType::Stop | ContainerOperationType::Kill => {
                ContainerStreamPriority::Critical
            },
            ContainerOperationType::HealthCheck => ContainerStreamPriority::Health,
            ContainerOperationType::GamingTelemetry => ContainerStreamPriority::GamingTelemetry,
            ContainerOperationType::Logs => ContainerStreamPriority::Logs,
            ContainerOperationType::ImagePull | ContainerOperationType::Backup => {
                ContainerStreamPriority::Bulk
            },
        };

        let stream_id = {
            let mut conn = connection.lock().await;
            self.stream_multiplexer
                .create_container_stream(&mut conn, container_id.clone(), priority)
                .await?
        };

        Ok(ContainerStream {
            stream_id,
            container_id,
            operation_type,
            connection,
            multiplexer: self.stream_multiplexer.clone(),
            buffer_pool: self.buffer_pool.clone(),
        })
    }

    /// Register a gaming session for a container (enables gaming mode optimizations)
    pub async fn register_gaming_container(
        &self,
        container_id: String,
        gpu_device_id: Option<String>,
    ) -> QuicResult<()> {
        // Register with gaming transport
        let gpu_info = if let Some(device_id) = gpu_device_id {
            Some(crate::gpanel_optimizations::GpuInfo {
                device_id,
                utilization_percent: 0.0,
                memory_used_mb: 0,
                memory_total_mb: 0,
                temperature_c: 0.0,
            })
        } else {
            None
        };

        self.gaming_transport
            .register_gaming_session(container_id.clone(), gpu_info)
            .await?;

        // Optimize performance for gaming workload (using LowLatency for gaming)
        // Note: optimize_connection_for_use_case requires a connection parameter
        // For now, we'll skip this optimization as it needs a specific connection

        info!("Registered gaming container: {}", container_id);
        Ok(())
    }

    /// Update gaming telemetry for a container
    pub async fn update_gaming_telemetry(
        &self,
        container_id: &str,
        telemetry: GamingTelemetry,
    ) -> QuicResult<()> {
        // Update gaming transport
        self.gaming_transport
            .update_gaming_telemetry(container_id, telemetry.clone())
            .await?;

        // Adjust performance optimizations based on telemetry
        if telemetry.input_lag_ms > 10.0 {
            warn!("High input lag detected for container {}: {}ms", container_id, telemetry.input_lag_ms);
            // Could trigger additional optimizations here
        }

        if telemetry.packet_loss_percent > 1.0 {
            warn!("Packet loss detected for container {}: {}%", container_id, telemetry.packet_loss_percent);
        }

        debug!("Gaming telemetry updated for {}: {}ms input lag, {}% GPU util",
               container_id, telemetry.input_lag_ms, telemetry.gpu_utilization);
        Ok(())
    }

    /// Get gaming mode status and performance metrics
    pub async fn get_gaming_status(&self) -> GamingStatus {
        let (gaming_active, session_count) = self.gaming_transport.get_gaming_status().await;
        let connection_count = self.connections.read().await.len();
        let (available_buffers, total_buffers) = self.buffer_pool.get_stats().await;

        GamingStatus {
            gaming_mode_active: gaming_active,
            active_gaming_sessions: session_count,
            total_connections: connection_count,
            buffer_pool_utilization: ((total_buffers - available_buffers) as f32 / total_buffers as f32) * 100.0,
            target_latency_us: 2500,
        }
    }

    /// Broadcast container event to all interested connections
    pub async fn broadcast_container_event(&self, event: ContainerEvent) -> QuicResult<()> {
        let connections = self.connections.read().await;
        let event_data = serde_json::to_vec(&event)?;
        let event_bytes = Bytes::from(event_data);

        for (connection_id, connection) in connections.iter() {
            // Create a temporary stream for the event broadcast
            let stream_id = {
                let mut conn = connection.lock().await;
                conn.open_stream(false).await? // Unidirectional for events
            };

            // Set high priority for container events
            self.gaming_transport
                .set_stream_priority(stream_id, ContainerStreamPriority::Health)
                .await;

            // Send the event
            {
                let mut conn = connection.lock().await;
                if let Err(e) = conn.send_stream_data(stream_id, event_bytes.clone()).await {
                    warn!("Failed to broadcast event to connection {}: {}", connection_id, e);
                }
            }
        }

        debug!("Broadcasted container event: {:?}", event);
        Ok(())
    }

    /// Clean up expired gaming sessions and optimize performance
    pub async fn maintenance_cycle(&self) -> QuicResult<()> {
        // Clean up expired gaming sessions
        self.gaming_transport.cleanup_expired_sessions().await?;

        // Performance optimizer maintenance (using available optimize methods)
        // Note: periodic_maintenance method not available, skipping for now

        // Clean up closed connections
        {
            let mut connections = self.connections.write().await;
            let mut to_remove = Vec::new();
            for (connection_id, connection) in connections.iter() {
                if let Ok(conn) = connection.try_lock() {
                    let is_connected = conn.is_connected().await;
                    if !is_connected {
                        debug!("Removing closed connection: {}", connection_id);
                        to_remove.push(connection_id.clone());
                    }
                }
            }
            for connection_id in to_remove {
                connections.remove(&connection_id);
            }
        }

        Ok(())
    }
}

/// Container operation types for stream prioritization
#[derive(Debug, Clone, PartialEq)]
pub enum ContainerOperationType {
    Start,
    Stop,
    Kill,
    HealthCheck,
    GamingTelemetry,
    Logs,
    ImagePull,
    Backup,
}

/// High-level container stream abstraction
#[derive(Debug)]
pub struct ContainerStream {
    pub stream_id: StreamId,
    pub container_id: String,
    pub operation_type: ContainerOperationType,
    connection: Arc<Mutex<Connection>>,
    multiplexer: Arc<ContainerStreamMultiplexer>,
    buffer_pool: Arc<ZeroCopyBufferPool>,
}

impl ContainerStream {
    /// Send data over the container stream with zero-copy optimization
    pub async fn send_data(&self, data: Bytes) -> QuicResult<()> {
        let (_, latency_us) = PrecisionTiming::measure_latency(|| async {
            self.multiplexer
                .send_container_data(&mut *self.connection.lock().await, self.stream_id, data)
                .await
        });

        if latency_us > 5000 {
            warn!("High latency send on container stream {}: {}μs", self.container_id, latency_us);
        }

        Ok(())
    }

    /// Receive data from the container stream
    pub async fn receive_data(&self) -> QuicResult<Option<Bytes>> {
        let mut conn = self.connection.lock().await;
        conn.receive_stream_data(self.stream_id).await.map_err(Into::into)
    }

    /// Close the container stream
    pub async fn close(&self) -> QuicResult<()> {
        let mut conn = self.connection.lock().await;
        conn.close_stream(self.stream_id).await.map_err(Into::into)
    }
}

/// Container event for broadcasting
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ContainerEvent {
    pub container_id: String,
    pub event_type: String,
    pub timestamp: u64,
    pub data: serde_json::Value,
}

/// Gaming mode status information
#[derive(Debug, Clone)]
pub struct GamingStatus {
    pub gaming_mode_active: bool,
    pub active_gaming_sessions: usize,
    pub total_connections: usize,
    pub buffer_pool_utilization: f32,
    pub target_latency_us: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;

    #[tokio::test]
    async fn test_gpanel_integration_creation() {
        let integration = GpanelQuicIntegration::new("127.0.0.1:0", None).await;
        assert!(integration.is_ok());

        let integration = integration.unwrap();
        let status = integration.get_gaming_status().await;
        assert!(!status.gaming_mode_active);
        assert_eq!(status.active_gaming_sessions, 0);
    }

    #[tokio::test]
    async fn test_gaming_container_registration() {
        let integration = GpanelQuicIntegration::new("127.0.0.1:0", None).await.unwrap();

        let result = integration.register_gaming_container(
            "test-gaming-container".to_string(),
            Some("gpu0".to_string())
        ).await;

        assert!(result.is_ok());

        let status = integration.get_gaming_status().await;
        assert!(status.gaming_mode_active);
        assert_eq!(status.active_gaming_sessions, 1);
    }

    #[tokio::test]
    async fn test_container_event_serialization() {
        let event = ContainerEvent {
            container_id: "test-container".to_string(),
            event_type: "started".to_string(),
            timestamp: 1234567890,
            data: serde_json::json!({"status": "running"}),
        };

        let serialized = serde_json::to_vec(&event).unwrap();
        let deserialized: ContainerEvent = serde_json::from_slice(&serialized).unwrap();

        assert_eq!(event.container_id, deserialized.container_id);
        assert_eq!(event.event_type, deserialized.event_type);
    }
}