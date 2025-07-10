use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Mutex, mpsc, oneshot};
use bytes::Bytes;
use tracing::{debug, info, warn, error};

use super::{ConnectionId, frame::Frame, error::{QuicError, Result}};

/// QUIC datagram support for unreliable, real-time data transmission
/// Perfect for crypto trading data, gaming, and other latency-sensitive applications
#[derive(Debug)]
pub struct DatagramManager {
    /// Outbound datagram queue
    outbound_queue: Arc<Mutex<VecDeque<DatagramFrame>>>,
    /// Inbound datagram handler
    inbound_handler: Arc<RwLock<Option<DatagramHandler>>>,
    /// Datagram configuration
    config: DatagramConfig,
    /// Connection state
    connection_state: Arc<RwLock<DatagramConnectionState>>,
    /// Statistics tracking
    stats: Arc<Mutex<DatagramStats>>,
}

#[derive(Debug, Clone)]
pub struct DatagramConfig {
    /// Enable datagram support
    pub enable_datagrams: bool,
    /// Maximum datagram payload size
    pub max_datagram_size: usize,
    /// Maximum outbound queue size
    pub max_outbound_queue_size: usize,
    /// Maximum inbound buffer size
    pub max_inbound_buffer_size: usize,
    /// Enable datagram prioritization
    pub enable_prioritization: bool,
    /// Datagram expiration timeout
    pub expiration_timeout: Duration,
    /// Enable datagram statistics
    pub enable_statistics: bool,
}

impl Default for DatagramConfig {
    fn default() -> Self {
        Self {
            enable_datagrams: true,
            max_datagram_size: 1200, // Conservative size for most networks
            max_outbound_queue_size: 1000,
            max_inbound_buffer_size: 2000,
            enable_prioritization: true,
            expiration_timeout: Duration::from_millis(5000), // 5 seconds
            enable_statistics: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DatagramFrame {
    /// Datagram payload
    pub data: Bytes,
    /// Priority (higher = more important)
    pub priority: DatagramPriority,
    /// Creation timestamp
    pub created_at: Instant,
    /// Expiration time
    pub expires_at: Option<Instant>,
    /// Datagram ID for tracking
    pub id: u64,
    /// Application-specific metadata
    pub metadata: Option<DatagramMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DatagramPriority {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3,
}

#[derive(Debug, Clone)]
pub struct DatagramMetadata {
    /// Application-specific type identifier
    pub message_type: String,
    /// Sequence number within type
    pub sequence: u64,
    /// Correlation ID for request/response patterns
    pub correlation_id: Option<String>,
    /// Custom key-value pairs
    pub attributes: HashMap<String, String>,
}

#[derive(Debug)]
struct DatagramConnectionState {
    /// Peer supports datagrams
    peer_supports_datagrams: bool,
    /// Maximum datagram size negotiated with peer
    negotiated_max_size: usize,
    /// Transport parameters received
    transport_params_received: bool,
    /// Connection ID for this datagram manager
    connection_id: ConnectionId,
}

#[derive(Debug, Default, Clone)]
struct DatagramStats {
    /// Total datagrams sent
    datagrams_sent: u64,
    /// Total datagrams received
    datagrams_received: u64,
    /// Total bytes sent in datagrams
    bytes_sent: u64,
    /// Total bytes received in datagrams
    bytes_received: u64,
    /// Datagrams dropped due to queue full
    datagrams_dropped_queue_full: u64,
    /// Datagrams dropped due to size limit
    datagrams_dropped_too_large: u64,
    /// Datagrams dropped due to expiration
    datagrams_dropped_expired: u64,
    /// Average datagram size sent
    avg_datagram_size_sent: f64,
    /// Average datagram size received
    avg_datagram_size_received: f64,
    /// Peak queue size
    peak_queue_size: usize,
}

/// Handler for received datagrams
#[derive(Debug)]
pub struct DatagramHandler {
    /// Channel for delivering received datagrams
    delivery_tx: mpsc::UnboundedSender<ReceivedDatagram>,
    /// Filter for datagram types
    filter: Option<DatagramFilter>,
}

#[derive(Debug, Clone)]
pub struct ReceivedDatagram {
    /// Datagram payload
    pub data: Bytes,
    /// Reception timestamp
    pub received_at: Instant,
    /// Connection ID
    pub connection_id: ConnectionId,
    /// Extracted metadata (if available)
    pub metadata: Option<DatagramMetadata>,
}

#[derive(Debug, Clone)]
pub struct DatagramFilter {
    /// Allowed message types
    pub allowed_types: Option<Vec<String>>,
    /// Maximum payload size to accept
    pub max_payload_size: Option<usize>,
    /// Custom filter function identifier
    pub custom_filter: Option<String>,
}

impl DatagramManager {
    pub fn new(connection_id: ConnectionId, config: DatagramConfig) -> Self {
        Self {
            outbound_queue: Arc::new(Mutex::new(VecDeque::new())),
            inbound_handler: Arc::new(RwLock::new(None)),
            config,
            connection_state: Arc::new(RwLock::new(DatagramConnectionState {
                peer_supports_datagrams: false,
                negotiated_max_size: config.max_datagram_size,
                transport_params_received: false,
                connection_id,
            })),
            stats: Arc::new(Mutex::new(DatagramStats::default())),
        }
    }

    /// Send a datagram with specified priority
    pub async fn send_datagram(
        &self,
        data: Bytes,
        priority: DatagramPriority,
        metadata: Option<DatagramMetadata>,
    ) -> Result<u64> {
        if !self.config.enable_datagrams {
            return Err(QuicError::Config("Datagrams not enabled".to_string()));
        }

        // Check peer support
        let state = self.connection_state.read().await;
        if !state.peer_supports_datagrams {
            return Err(QuicError::Config("Peer does not support datagrams".to_string()));
        }

        // Check size limit
        if data.len() > state.negotiated_max_size {
            let mut stats = self.stats.lock().await;
            stats.datagrams_dropped_too_large += 1;
            return Err(QuicError::Config(format!(
                "Datagram too large: {} > {}", 
                data.len(), 
                state.negotiated_max_size
            )));
        }

        drop(state);

        let now = Instant::now();
        let expires_at = if self.config.expiration_timeout.as_millis() > 0 {
            Some(now + self.config.expiration_timeout)
        } else {
            None
        };

        let id = self.generate_datagram_id().await;
        let datagram = DatagramFrame {
            data: data.clone(),
            priority,
            created_at: now,
            expires_at,
            id,
            metadata,
        };

        // Add to outbound queue
        let mut queue = self.outbound_queue.lock().await;
        
        // Check queue size limit
        if queue.len() >= self.config.max_outbound_queue_size {
            // Remove lowest priority expired datagrams first
            self.cleanup_expired_datagrams(&mut queue, now);
            
            if queue.len() >= self.config.max_outbound_queue_size {
                // Drop lowest priority datagram
                if let Some(pos) = queue.iter().position(|d| d.priority == DatagramPriority::Low) {
                    queue.remove(pos);
                } else {
                    // Queue still full, drop this datagram
                    let mut stats = self.stats.lock().await;
                    stats.datagrams_dropped_queue_full += 1;
                    return Err(QuicError::Config("Datagram queue full".to_string()));
                }
            }
        }

        // Insert datagram in priority order
        let insert_pos = queue.partition_point(|d| d.priority > priority);
        queue.insert(insert_pos, datagram);

        // Update statistics
        let mut stats = self.stats.lock().await;
        stats.peak_queue_size = stats.peak_queue_size.max(queue.len());

        debug!("Queued datagram {} with priority {:?} ({} bytes)", 
               id, priority, data.len());

        Ok(id)
    }

    /// Get next datagram frame to send
    pub async fn get_next_datagram(&self) -> Option<Frame> {
        let mut queue = self.outbound_queue.lock().await;
        
        // Clean up expired datagrams
        let now = Instant::now();
        self.cleanup_expired_datagrams(&mut queue, now);

        // Get highest priority datagram
        if let Some(datagram) = queue.pop_front() {
            // Update statistics
            tokio::spawn({
                let stats = self.stats.clone();
                let data_len = datagram.data.len();
                async move {
                    let mut stats = stats.lock().await;
                    stats.datagrams_sent += 1;
                    stats.bytes_sent += data_len as u64;
                    
                    // Update average size
                    if stats.datagrams_sent == 1 {
                        stats.avg_datagram_size_sent = data_len as f64;
                    } else {
                        stats.avg_datagram_size_sent = 
                            (stats.avg_datagram_size_sent * (stats.datagrams_sent - 1) as f64 + data_len as f64) 
                            / stats.datagrams_sent as f64;
                    }
                }
            });

            debug!("Sending datagram {} ({} bytes)", datagram.id, datagram.data.len());

            Some(Frame::Datagram {
                data: datagram.data,
            })
        } else {
            None
        }
    }

    /// Process received datagram frame
    pub async fn on_datagram_received(&self, data: Bytes) -> Result<()> {
        if !self.config.enable_datagrams {
            return Ok(()); // Silently ignore if disabled
        }

        let now = Instant::now();
        let connection_id = self.connection_state.read().await.connection_id.clone();

        // Extract metadata if possible
        let metadata = self.extract_metadata(&data).await;

        let received_datagram = ReceivedDatagram {
            data: data.clone(),
            received_at: now,
            connection_id,
            metadata,
        };

        // Apply filter
        if !self.should_accept_datagram(&received_datagram).await {
            debug!("Filtered out received datagram ({} bytes)", data.len());
            return Ok(());
        }

        // Deliver to handler
        let handler = self.inbound_handler.read().await;
        if let Some(ref handler) = *handler {
            if let Err(_) = handler.delivery_tx.send(received_datagram) {
                warn!("Failed to deliver received datagram - handler channel closed");
            }
        }

        // Update statistics
        let mut stats = self.stats.lock().await;
        stats.datagrams_received += 1;
        stats.bytes_received += data.len() as u64;
        
        // Update average size
        if stats.datagrams_received == 1 {
            stats.avg_datagram_size_received = data.len() as f64;
        } else {
            stats.avg_datagram_size_received = 
                (stats.avg_datagram_size_received * (stats.datagrams_received - 1) as f64 + data.len() as f64) 
                / stats.datagrams_received as f64;
        }

        debug!("Received datagram ({} bytes)", data.len());
        Ok(())
    }

    /// Set datagram handler
    pub async fn set_handler(
        &self,
        handler_tx: mpsc::UnboundedSender<ReceivedDatagram>,
        filter: Option<DatagramFilter>,
    ) {
        let handler = DatagramHandler {
            delivery_tx: handler_tx,
            filter,
        };
        
        let mut inbound_handler = self.inbound_handler.write().await;
        *inbound_handler = Some(handler);
        
        info!("Datagram handler configured");
    }

    /// Update peer datagram support from transport parameters
    pub async fn update_peer_support(&self, max_datagram_size: Option<usize>) {
        let mut state = self.connection_state.write().await;
        
        if let Some(size) = max_datagram_size {
            state.peer_supports_datagrams = true;
            state.negotiated_max_size = size.min(self.config.max_datagram_size);
            
            info!("Peer supports datagrams (max size: {})", state.negotiated_max_size);
        } else {
            state.peer_supports_datagrams = false;
            warn!("Peer does not support datagrams");
        }
        
        state.transport_params_received = true;
    }

    /// Check if datagrams are supported by peer
    pub async fn is_supported(&self) -> bool {
        let state = self.connection_state.read().await;
        state.peer_supports_datagrams
    }

    /// Get maximum datagram size
    pub async fn max_datagram_size(&self) -> usize {
        let state = self.connection_state.read().await;
        state.negotiated_max_size
    }

    /// Generate unique datagram ID
    async fn generate_datagram_id(&self) -> u64 {
        let stats = self.stats.lock().await;
        stats.datagrams_sent + 1
    }

    /// Clean up expired datagrams from queue
    fn cleanup_expired_datagrams(&self, queue: &mut VecDeque<DatagramFrame>, now: Instant) {
        let original_len = queue.len();
        queue.retain(|datagram| {
            if let Some(expires_at) = datagram.expires_at {
                expires_at > now
            } else {
                true
            }
        });
        
        let expired_count = original_len - queue.len();
        if expired_count > 0 {
            tokio::spawn({
                let stats = self.stats.clone();
                async move {
                    let mut stats = stats.lock().await;
                    stats.datagrams_dropped_expired += expired_count as u64;
                }
            });
            
            debug!("Cleaned up {} expired datagrams", expired_count);
        }
    }

    /// Extract metadata from datagram payload
    async fn extract_metadata(&self, data: &Bytes) -> Option<DatagramMetadata> {
        // Simple metadata extraction - in practice this could be more sophisticated
        if data.len() < 8 {
            return None;
        }

        // Check for magic header (simplified)
        if &data[0..4] == b"META" {
            // Extract basic metadata
            let sequence = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as u64;
            
            Some(DatagramMetadata {
                message_type: "unknown".to_string(),
                sequence,
                correlation_id: None,
                attributes: HashMap::new(),
            })
        } else {
            None
        }
    }

    /// Check if datagram should be accepted based on filter
    async fn should_accept_datagram(&self, datagram: &ReceivedDatagram) -> bool {
        let handler = self.inbound_handler.read().await;
        if let Some(ref handler) = *handler {
            if let Some(ref filter) = handler.filter {
                // Check size limit
                if let Some(max_size) = filter.max_payload_size {
                    if datagram.data.len() > max_size {
                        return false;
                    }
                }

                // Check message type
                if let Some(ref allowed_types) = filter.allowed_types {
                    if let Some(ref metadata) = datagram.metadata {
                        if !allowed_types.contains(&metadata.message_type) {
                            return false;
                        }
                    } else {
                        // No metadata, reject if types are restricted
                        return false;
                    }
                }
            }
        }

        true
    }

    /// Get queue status
    pub async fn get_queue_status(&self) -> QueueStatus {
        let queue = self.outbound_queue.lock().await;
        let now = Instant::now();
        
        let mut priority_counts = HashMap::new();
        let mut expired_count = 0;
        
        for datagram in queue.iter() {
            *priority_counts.entry(datagram.priority.clone()).or_insert(0) += 1;
            
            if let Some(expires_at) = datagram.expires_at {
                if expires_at <= now {
                    expired_count += 1;
                }
            }
        }

        QueueStatus {
            total_queued: queue.len(),
            priority_counts,
            expired_count,
            queue_capacity: self.config.max_outbound_queue_size,
        }
    }

    /// Get datagram statistics
    pub async fn get_stats(&self) -> DatagramStats {
        self.stats.lock().await.clone()
    }

    /// Clear outbound queue
    pub async fn clear_queue(&self) {
        let mut queue = self.outbound_queue.lock().await;
        let cleared_count = queue.len();
        queue.clear();
        
        info!("Cleared {} datagrams from outbound queue", cleared_count);
    }

    /// Create real-time data sender for crypto applications
    pub fn create_realtime_sender(&self) -> RealtimeDatagramSender {
        RealtimeDatagramSender {
            manager: self.clone(),
            default_priority: DatagramPriority::High,
            sequence_counter: Arc::new(Mutex::new(0)),
        }
    }
}

impl Clone for DatagramManager {
    fn clone(&self) -> Self {
        Self {
            outbound_queue: self.outbound_queue.clone(),
            inbound_handler: self.inbound_handler.clone(),
            config: self.config.clone(),
            connection_state: self.connection_state.clone(),
            stats: self.stats.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct QueueStatus {
    pub total_queued: usize,
    pub priority_counts: HashMap<DatagramPriority, usize>,
    pub expired_count: usize,
    pub queue_capacity: usize,
}

/// Specialized sender for real-time crypto data
#[derive(Debug)]
pub struct RealtimeDatagramSender {
    manager: DatagramManager,
    default_priority: DatagramPriority,
    sequence_counter: Arc<Mutex<u64>>,
}

impl RealtimeDatagramSender {
    /// Send market data update
    pub async fn send_market_data(&self, symbol: &str, data: &[u8]) -> Result<u64> {
        let sequence = {
            let mut counter = self.sequence_counter.lock().await;
            *counter += 1;
            *counter
        };

        let metadata = DatagramMetadata {
            message_type: "market_data".to_string(),
            sequence,
            correlation_id: Some(symbol.to_string()),
            attributes: {
                let mut attrs = HashMap::new();
                attrs.insert("symbol".to_string(), symbol.to_string());
                attrs.insert("type".to_string(), "price_update".to_string());
                attrs
            },
        };

        self.manager.send_datagram(
            Bytes::copy_from_slice(data),
            DatagramPriority::Critical,
            Some(metadata),
        ).await
    }

    /// Send trading signal
    pub async fn send_trading_signal(&self, signal_data: &[u8]) -> Result<u64> {
        let sequence = {
            let mut counter = self.sequence_counter.lock().await;
            *counter += 1;
            *counter
        };

        let metadata = DatagramMetadata {
            message_type: "trading_signal".to_string(),
            sequence,
            correlation_id: None,
            attributes: {
                let mut attrs = HashMap::new();
                attrs.insert("type".to_string(), "signal".to_string());
                attrs
            },
        };

        self.manager.send_datagram(
            Bytes::copy_from_slice(signal_data),
            DatagramPriority::High,
            Some(metadata),
        ).await
    }

    /// Send heartbeat
    pub async fn send_heartbeat(&self) -> Result<u64> {
        let heartbeat_data = b"HEARTBEAT";
        
        self.manager.send_datagram(
            Bytes::from_static(heartbeat_data),
            DatagramPriority::Low,
            None,
        ).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_datagram_send_receive() {
        let connection_id = ConnectionId::new();
        let manager = DatagramManager::new(connection_id, DatagramConfig::default());
        
        // Enable peer support
        manager.update_peer_support(Some(1200)).await;
        
        // Set up handler
        let (tx, mut rx) = mpsc::unbounded_channel();
        manager.set_handler(tx, None).await;
        
        // Send datagram
        let test_data = Bytes::from("Hello, World!");
        let id = manager.send_datagram(
            test_data.clone(),
            DatagramPriority::Normal,
            None,
        ).await.unwrap();
        
        assert!(id > 0);
        
        // Get frame
        let frame = manager.get_next_datagram().await;
        assert!(frame.is_some());
        
        // Simulate receiving
        manager.on_datagram_received(test_data.clone()).await.unwrap();
        
        // Check received
        let received = rx.recv().await.unwrap();
        assert_eq!(received.data, test_data);
    }

    #[tokio::test]
    async fn test_datagram_priority_ordering() {
        let connection_id = ConnectionId::new();
        let manager = DatagramManager::new(connection_id, DatagramConfig::default());
        
        // Enable peer support
        manager.update_peer_support(Some(1200)).await;
        
        // Send datagrams with different priorities
        manager.send_datagram(
            Bytes::from("low"),
            DatagramPriority::Low,
            None,
        ).await.unwrap();
        
        manager.send_datagram(
            Bytes::from("critical"),
            DatagramPriority::Critical,
            None,
        ).await.unwrap();
        
        manager.send_datagram(
            Bytes::from("normal"),
            DatagramPriority::Normal,
            None,
        ).await.unwrap();
        
        // Should get critical first
        let frame1 = manager.get_next_datagram().await.unwrap();
        if let Frame::Datagram { data } = frame1 {
            assert_eq!(data, Bytes::from("critical"));
        }
        
        // Then normal
        let frame2 = manager.get_next_datagram().await.unwrap();
        if let Frame::Datagram { data } = frame2 {
            assert_eq!(data, Bytes::from("normal"));
        }
        
        // Finally low
        let frame3 = manager.get_next_datagram().await.unwrap();
        if let Frame::Datagram { data } = frame3 {
            assert_eq!(data, Bytes::from("low"));
        }
    }

    #[tokio::test]
    async fn test_realtime_sender() {
        let connection_id = ConnectionId::new();
        let manager = DatagramManager::new(connection_id, DatagramConfig::default());
        
        // Enable peer support
        manager.update_peer_support(Some(1200)).await;
        
        let sender = manager.create_realtime_sender();
        
        // Send market data
        let id = sender.send_market_data("BTC/USD", b"price:50000").await.unwrap();
        assert!(id > 0);
        
        // Send trading signal
        let id = sender.send_trading_signal(b"BUY_SIGNAL").await.unwrap();
        assert!(id > 0);
        
        // Send heartbeat
        let id = sender.send_heartbeat().await.unwrap();
        assert!(id > 0);
    }
}