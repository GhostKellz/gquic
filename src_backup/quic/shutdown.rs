use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Mutex, mpsc, oneshot};
use tokio::time::timeout;
use tracing::{debug, info, warn, error};

use super::{ConnectionId, StreamId, frame::Frame, error::{QuicError, Result}};

/// Graceful shutdown manager for QUIC connections and streams
#[derive(Debug)]
pub struct ShutdownManager {
    /// Shutdown state for connections
    connection_shutdowns: Arc<RwLock<HashMap<ConnectionId, ConnectionShutdown>>>,
    /// Shutdown state for streams
    stream_shutdowns: Arc<RwLock<HashMap<StreamId, StreamShutdown>>>,
    /// Shutdown configuration
    config: ShutdownConfig,
    /// Shutdown coordinator
    coordinator: Arc<Mutex<ShutdownCoordinator>>,
}

#[derive(Debug, Clone)]
pub struct ShutdownConfig {
    /// Maximum time to wait for graceful shutdown
    pub graceful_timeout: Duration,
    /// Maximum time to wait for connection close
    pub connection_close_timeout: Duration,
    /// Maximum time to wait for stream close
    pub stream_close_timeout: Duration,
    /// Enable immediate shutdown on timeout
    pub enable_immediate_shutdown: bool,
    /// Send CONNECTION_CLOSE on shutdown
    pub send_connection_close: bool,
    /// Drain timeout for pending data
    pub drain_timeout: Duration,
}

impl Default for ShutdownConfig {
    fn default() -> Self {
        Self {
            graceful_timeout: Duration::from_secs(30),
            connection_close_timeout: Duration::from_secs(10),
            stream_close_timeout: Duration::from_secs(5),
            enable_immediate_shutdown: true,
            send_connection_close: true,
            drain_timeout: Duration::from_secs(15),
        }
    }
}

#[derive(Debug)]
struct ConnectionShutdown {
    connection_id: ConnectionId,
    state: ShutdownState,
    start_time: Instant,
    close_reason: Option<CloseReason>,
    pending_streams: Vec<StreamId>,
    shutdown_tx: Option<oneshot::Sender<ShutdownResult>>,
    frames_to_send: VecDeque<Frame>,
}

#[derive(Debug)]
struct StreamShutdown {
    stream_id: StreamId,
    connection_id: ConnectionId,
    state: ShutdownState,
    start_time: Instant,
    close_reason: Option<CloseReason>,
    pending_data: Option<Vec<u8>>,
    shutdown_tx: Option<oneshot::Sender<ShutdownResult>>,
}

#[derive(Debug, Clone)]
struct ShutdownCoordinator {
    active_shutdowns: HashMap<ConnectionId, ShutdownHandle>,
    shutdown_queue: VecDeque<ShutdownRequest>,
    global_shutdown: bool,
    shutdown_start_time: Option<Instant>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ShutdownState {
    NotStarted,
    Initiated,
    Draining,
    WaitingForAck,
    Completed,
    Failed,
    Timeout,
}

#[derive(Debug, Clone)]
pub enum CloseReason {
    UserRequested,
    IdleTimeout,
    ProtocolError(String),
    ApplicationError(u64, String),
    NetworkError(String),
    Shutdown,
}

#[derive(Debug)]
struct ShutdownHandle {
    connection_id: ConnectionId,
    shutdown_tx: mpsc::Sender<ShutdownCommand>,
    completion_rx: Option<oneshot::Receiver<ShutdownResult>>,
}

#[derive(Debug)]
enum ShutdownCommand {
    InitiateShutdown(CloseReason),
    DrainConnection,
    ForceClose,
    AddStream(StreamId),
    RemoveStream(StreamId),
}

#[derive(Debug)]
struct ShutdownRequest {
    connection_id: ConnectionId,
    reason: CloseReason,
    priority: ShutdownPriority,
    requested_at: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum ShutdownPriority {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3,
}

#[derive(Debug, Clone)]
pub enum ShutdownResult {
    Graceful,
    Timeout,
    Forced,
    Error(String),
}

impl ShutdownManager {
    pub fn new(config: ShutdownConfig) -> Self {
        Self {
            connection_shutdowns: Arc::new(RwLock::new(HashMap::new())),
            stream_shutdowns: Arc::new(RwLock::new(HashMap::new())),
            config,
            coordinator: Arc::new(Mutex::new(ShutdownCoordinator {
                active_shutdowns: HashMap::new(),
                shutdown_queue: VecDeque::new(),
                global_shutdown: false,
                shutdown_start_time: None,
            })),
        }
    }

    /// Initiate graceful shutdown for a connection
    pub async fn shutdown_connection(
        &self,
        connection_id: ConnectionId,
        reason: CloseReason,
    ) -> Result<oneshot::Receiver<ShutdownResult>> {
        let (tx, rx) = oneshot::channel();
        let now = Instant::now();

        let mut connection_shutdown = ConnectionShutdown {
            connection_id: connection_id.clone(),
            state: ShutdownState::Initiated,
            start_time: now,
            close_reason: Some(reason.clone()),
            pending_streams: Vec::new(),
            shutdown_tx: Some(tx),
            frames_to_send: VecDeque::new(),
        };

        // Prepare CONNECTION_CLOSE frame if needed
        if self.config.send_connection_close {
            let close_frame = self.create_connection_close_frame(&reason);
            connection_shutdown.frames_to_send.push_back(close_frame);
        }

        let mut shutdowns = self.connection_shutdowns.write().await;
        shutdowns.insert(connection_id.clone(), connection_shutdown);

        info!("Initiated graceful shutdown for connection {} (reason: {:?})", 
              connection_id, reason);

        Ok(rx)
    }

    /// Initiate graceful shutdown for a stream
    pub async fn shutdown_stream(
        &self,
        stream_id: StreamId,
        connection_id: ConnectionId,
        reason: CloseReason,
    ) -> Result<oneshot::Receiver<ShutdownResult>> {
        let (tx, rx) = oneshot::channel();
        let now = Instant::now();

        let stream_shutdown = StreamShutdown {
            stream_id,
            connection_id: connection_id.clone(),
            state: ShutdownState::Initiated,
            start_time: now,
            close_reason: Some(reason.clone()),
            pending_data: None,
            shutdown_tx: Some(tx),
        };

        let mut shutdowns = self.stream_shutdowns.write().await;
        shutdowns.insert(stream_id, stream_shutdown);

        // Update connection shutdown to track this stream
        let mut connection_shutdowns = self.connection_shutdowns.write().await;
        if let Some(conn_shutdown) = connection_shutdowns.get_mut(&connection_id) {
            conn_shutdown.pending_streams.push(stream_id);
        }

        debug!("Initiated stream shutdown for {} on connection {} (reason: {:?})", 
               stream_id, connection_id, reason);

        Ok(rx)
    }

    /// Process shutdown progress and timeouts
    pub async fn process_shutdowns(&self) -> Result<Vec<Frame>> {
        let now = Instant::now();
        let mut frames_to_send = Vec::new();

        // Process connection shutdowns
        {
            let mut shutdowns = self.connection_shutdowns.write().await;
            let mut completed_connections = Vec::new();

            for (connection_id, shutdown) in shutdowns.iter_mut() {
                match self.process_connection_shutdown(shutdown, now).await? {
                    ShutdownProgress::Completed(result) => {
                        if let Some(tx) = shutdown.shutdown_tx.take() {
                            let _ = tx.send(result);
                        }
                        completed_connections.push(*connection_id);
                    }
                    ShutdownProgress::SendFrames(mut frames) => {
                        frames_to_send.append(&mut frames);
                    }
                    ShutdownProgress::Continue => {}
                }
            }

            // Remove completed shutdowns
            for connection_id in completed_connections {
                shutdowns.remove(&connection_id);
                info!("Completed shutdown for connection {}", connection_id);
            }
        }

        // Process stream shutdowns
        {
            let mut shutdowns = self.stream_shutdowns.write().await;
            let mut completed_streams = Vec::new();

            for (stream_id, shutdown) in shutdowns.iter_mut() {
                match self.process_stream_shutdown(shutdown, now).await? {
                    ShutdownProgress::Completed(result) => {
                        if let Some(tx) = shutdown.shutdown_tx.take() {
                            let _ = tx.send(result);
                        }
                        completed_streams.push(*stream_id);
                    }
                    ShutdownProgress::SendFrames(mut frames) => {
                        frames_to_send.append(&mut frames);
                    }
                    ShutdownProgress::Continue => {}
                }
            }

            // Remove completed shutdowns
            for stream_id in completed_streams {
                shutdowns.remove(&stream_id);
                debug!("Completed shutdown for stream {}", stream_id);
            }
        }

        Ok(frames_to_send)
    }

    /// Process individual connection shutdown
    async fn process_connection_shutdown(
        &self,
        shutdown: &mut ConnectionShutdown,
        now: Instant,
    ) -> Result<ShutdownProgress> {
        let elapsed = now.duration_since(shutdown.start_time);

        match shutdown.state {
            ShutdownState::Initiated => {
                // Send initial frames
                if !shutdown.frames_to_send.is_empty() {
                    let frames: Vec<Frame> = shutdown.frames_to_send.drain(..).collect();
                    shutdown.state = ShutdownState::Draining;
                    return Ok(ShutdownProgress::SendFrames(frames));
                }
                shutdown.state = ShutdownState::Draining;
                Ok(ShutdownProgress::Continue)
            }
            ShutdownState::Draining => {
                // Wait for pending streams to close
                if shutdown.pending_streams.is_empty() {
                    shutdown.state = ShutdownState::WaitingForAck;
                } else if elapsed > self.config.drain_timeout {
                    warn!("Drain timeout for connection {}, forcing closure", 
                          shutdown.connection_id);
                    shutdown.state = ShutdownState::Timeout;
                    return Ok(ShutdownProgress::Completed(ShutdownResult::Timeout));
                }
                Ok(ShutdownProgress::Continue)
            }
            ShutdownState::WaitingForAck => {
                // Check for completion or timeout
                if elapsed > self.config.connection_close_timeout {
                    shutdown.state = ShutdownState::Timeout;
                    Ok(ShutdownProgress::Completed(ShutdownResult::Timeout))
                } else {
                    Ok(ShutdownProgress::Continue)
                }
            }
            ShutdownState::Completed => {
                Ok(ShutdownProgress::Completed(ShutdownResult::Graceful))
            }
            ShutdownState::Failed => {
                Ok(ShutdownProgress::Completed(ShutdownResult::Error(
                    "Shutdown failed".to_string()
                )))
            }
            ShutdownState::Timeout => {
                Ok(ShutdownProgress::Completed(ShutdownResult::Timeout))
            }
            _ => Ok(ShutdownProgress::Continue),
        }
    }

    /// Process individual stream shutdown
    async fn process_stream_shutdown(
        &self,
        shutdown: &mut StreamShutdown,
        now: Instant,
    ) -> Result<ShutdownProgress> {
        let elapsed = now.duration_since(shutdown.start_time);

        match shutdown.state {
            ShutdownState::Initiated => {
                // Send stream close frames
                let mut frames = Vec::new();
                
                // Send any pending data first
                if let Some(data) = shutdown.pending_data.take() {
                    frames.push(Frame::Stream {
                        stream_id: shutdown.stream_id,
                        offset: 0, // Simplified
                        data: data.into(),
                        fin: true,
                    });
                }

                // Send RESET_STREAM frame for immediate closure
                frames.push(Frame::ResetStream {
                    stream_id: shutdown.stream_id,
                    application_error_code: 0,
                    final_size: 0, // Simplified
                });

                shutdown.state = ShutdownState::WaitingForAck;
                Ok(ShutdownProgress::SendFrames(frames))
            }
            ShutdownState::WaitingForAck => {
                if elapsed > self.config.stream_close_timeout {
                    shutdown.state = ShutdownState::Timeout;
                    Ok(ShutdownProgress::Completed(ShutdownResult::Timeout))
                } else {
                    Ok(ShutdownProgress::Continue)
                }
            }
            ShutdownState::Completed => {
                Ok(ShutdownProgress::Completed(ShutdownResult::Graceful))
            }
            _ => Ok(ShutdownProgress::Continue),
        }
    }

    /// Create CONNECTION_CLOSE frame
    fn create_connection_close_frame(&self, reason: &CloseReason) -> Frame {
        match reason {
            CloseReason::ApplicationError(code, message) => {
                Frame::ApplicationClose {
                    error_code: *code,
                    reason_phrase: message.clone(),
                }
            }
            CloseReason::ProtocolError(message) => {
                Frame::ConnectionClose {
                    error_code: 0x01, // PROTOCOL_VIOLATION
                    frame_type: None,
                    reason_phrase: message.clone(),
                }
            }
            _ => {
                Frame::ConnectionClose {
                    error_code: 0x00, // NO_ERROR
                    frame_type: None,
                    reason_phrase: "Graceful shutdown".to_string(),
                }
            }
        }
    }

    /// Mark connection shutdown as acknowledged
    pub async fn mark_connection_ack(&self, connection_id: &ConnectionId) -> Result<()> {
        let mut shutdowns = self.connection_shutdowns.write().await;
        if let Some(shutdown) = shutdowns.get_mut(connection_id) {
            if shutdown.state == ShutdownState::WaitingForAck {
                shutdown.state = ShutdownState::Completed;
                debug!("Connection {} shutdown acknowledged", connection_id);
            }
        }
        Ok(())
    }

    /// Mark stream shutdown as acknowledged
    pub async fn mark_stream_ack(&self, stream_id: &StreamId) -> Result<()> {
        let mut shutdowns = self.stream_shutdowns.write().await;
        if let Some(shutdown) = shutdowns.get_mut(stream_id) {
            if shutdown.state == ShutdownState::WaitingForAck {
                shutdown.state = ShutdownState::Completed;
                debug!("Stream {} shutdown acknowledged", stream_id);

                // Remove from connection's pending streams
                let connection_id = shutdown.connection_id;
                drop(shutdowns); // Release lock before acquiring another

                let mut connection_shutdowns = self.connection_shutdowns.write().await;
                if let Some(conn_shutdown) = connection_shutdowns.get_mut(&connection_id) {
                    conn_shutdown.pending_streams.retain(|&s| s != *stream_id);
                }
            }
        }
        Ok(())
    }

    /// Force immediate shutdown (emergency)
    pub async fn force_shutdown(&self, connection_id: &ConnectionId) -> Result<()> {
        let mut shutdowns = self.connection_shutdowns.write().await;
        if let Some(shutdown) = shutdowns.get_mut(connection_id) {
            shutdown.state = ShutdownState::Completed;
            if let Some(tx) = shutdown.shutdown_tx.take() {
                let _ = tx.send(ShutdownResult::Forced);
            }
            warn!("Forced immediate shutdown for connection {}", connection_id);
        }
        Ok(())
    }

    /// Initiate global shutdown
    pub async fn shutdown_all(&self, reason: CloseReason) -> Result<Vec<oneshot::Receiver<ShutdownResult>>> {
        let mut coordinator = self.coordinator.lock().await;
        coordinator.global_shutdown = true;
        coordinator.shutdown_start_time = Some(Instant::now());

        let mut receivers = Vec::new();
        let shutdowns = self.connection_shutdowns.read().await;
        let connection_ids: Vec<ConnectionId> = shutdowns.keys().cloned().collect();
        drop(shutdowns);

        for connection_id in connection_ids {
            let rx = self.shutdown_connection(connection_id, reason.clone()).await?;
            receivers.push(rx);
        }

        info!("Initiated global shutdown (reason: {:?})", reason);
        Ok(receivers)
    }

    /// Wait for all shutdowns to complete
    pub async fn wait_for_shutdown_completion(&self) -> Result<()> {
        let timeout_duration = self.config.graceful_timeout;
        
        match timeout(timeout_duration, self.wait_for_all_shutdowns()).await {
            Ok(_) => {
                info!("All shutdowns completed gracefully");
                Ok(())
            }
            Err(_) => {
                warn!("Shutdown timeout reached, forcing remaining shutdowns");
                self.force_all_shutdowns().await?;
                Err(QuicError::Config("Shutdown timeout".to_string()))
            }
        }
    }

    /// Wait for all shutdowns to complete (internal)
    async fn wait_for_all_shutdowns(&self) {
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;
            
            let connection_count = self.connection_shutdowns.read().await.len();
            let stream_count = self.stream_shutdowns.read().await.len();
            
            if connection_count == 0 && stream_count == 0 {
                break;
            }
        }
    }

    /// Force all remaining shutdowns
    async fn force_all_shutdowns(&self) -> Result<()> {
        let shutdowns = self.connection_shutdowns.read().await;
        let connection_ids: Vec<ConnectionId> = shutdowns.keys().cloned().collect();
        drop(shutdowns);

        for connection_id in connection_ids {
            self.force_shutdown(&connection_id).await?;
        }

        Ok(())
    }

    /// Get shutdown statistics
    pub async fn get_stats(&self) -> ShutdownStats {
        let connection_shutdowns = self.connection_shutdowns.read().await;
        let stream_shutdowns = self.stream_shutdowns.read().await;
        let coordinator = self.coordinator.lock().await;

        ShutdownStats {
            active_connection_shutdowns: connection_shutdowns.len(),
            active_stream_shutdowns: stream_shutdowns.len(),
            global_shutdown_active: coordinator.global_shutdown,
            shutdown_start_time: coordinator.shutdown_start_time,
            queued_shutdowns: coordinator.shutdown_queue.len(),
        }
    }
}

#[derive(Debug)]
enum ShutdownProgress {
    Continue,
    SendFrames(Vec<Frame>),
    Completed(ShutdownResult),
}

#[derive(Debug, Clone)]
pub struct ShutdownStats {
    pub active_connection_shutdowns: usize,
    pub active_stream_shutdowns: usize,
    pub global_shutdown_active: bool,
    pub shutdown_start_time: Option<Instant>,
    pub queued_shutdowns: usize,
}

/// Cleanup manager for resources after shutdown
#[derive(Debug)]
pub struct CleanupManager {
    cleanup_tasks: Arc<RwLock<HashMap<String, CleanupTask>>>,
    config: CleanupConfig,
}

#[derive(Debug, Clone)]
pub struct CleanupConfig {
    /// Maximum time to wait for cleanup
    pub cleanup_timeout: Duration,
    /// Enable parallel cleanup
    pub enable_parallel_cleanup: bool,
    /// Maximum concurrent cleanup tasks
    pub max_concurrent_cleanups: usize,
}

impl Default for CleanupConfig {
    fn default() -> Self {
        Self {
            cleanup_timeout: Duration::from_secs(30),
            enable_parallel_cleanup: true,
            max_concurrent_cleanups: 10,
        }
    }
}

#[derive(Debug)]
struct CleanupTask {
    id: String,
    description: String,
    start_time: Instant,
    timeout: Duration,
    completed: bool,
}

impl CleanupManager {
    pub fn new(config: CleanupConfig) -> Self {
        Self {
            cleanup_tasks: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Register a cleanup task
    pub async fn register_cleanup_task(
        &self,
        id: String,
        description: String,
        timeout: Duration,
    ) -> Result<()> {
        let task = CleanupTask {
            id: id.clone(),
            description,
            start_time: Instant::now(),
            timeout,
            completed: false,
        };

        let mut tasks = self.cleanup_tasks.write().await;
        tasks.insert(id, task);
        Ok(())
    }

    /// Mark cleanup task as completed
    pub async fn complete_cleanup_task(&self, id: &str) -> Result<()> {
        let mut tasks = self.cleanup_tasks.write().await;
        if let Some(task) = tasks.get_mut(id) {
            task.completed = true;
            debug!("Cleanup task '{}' completed", id);
        }
        Ok(())
    }

    /// Run all cleanup tasks
    pub async fn run_cleanup(&self) -> Result<()> {
        let tasks = self.cleanup_tasks.read().await;
        let task_ids: Vec<String> = tasks.keys().cloned().collect();
        drop(tasks);

        if self.config.enable_parallel_cleanup {
            self.run_parallel_cleanup(task_ids).await
        } else {
            self.run_sequential_cleanup(task_ids).await
        }
    }

    async fn run_parallel_cleanup(&self, task_ids: Vec<String>) -> Result<()> {
        // Simplified parallel cleanup - in production would use proper task management
        for id in task_ids {
            self.complete_cleanup_task(&id).await?;
        }
        Ok(())
    }

    async fn run_sequential_cleanup(&self, task_ids: Vec<String>) -> Result<()> {
        for id in task_ids {
            self.complete_cleanup_task(&id).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_connection_shutdown() {
        let manager = ShutdownManager::new(ShutdownConfig::default());
        let connection_id = ConnectionId::new();
        let reason = CloseReason::UserRequested;

        let rx = manager.shutdown_connection(connection_id, reason).await.unwrap();
        
        // Process shutdowns
        let frames = manager.process_shutdowns().await.unwrap();
        assert!(!frames.is_empty());

        // Mark as acknowledged
        manager.mark_connection_ack(&connection_id).await.unwrap();
        
        // Should complete
        let result = timeout(Duration::from_secs(1), rx).await.unwrap().unwrap();
        matches!(result, ShutdownResult::Graceful);
    }

    #[tokio::test]
    async fn test_stream_shutdown() {
        let manager = ShutdownManager::new(ShutdownConfig::default());
        let stream_id = StreamId::new(0);
        let connection_id = ConnectionId::new();
        let reason = CloseReason::UserRequested;

        let rx = manager.shutdown_stream(stream_id, connection_id, reason).await.unwrap();
        
        // Process shutdowns
        let frames = manager.process_shutdowns().await.unwrap();
        assert!(!frames.is_empty());

        // Mark as acknowledged
        manager.mark_stream_ack(&stream_id).await.unwrap();
        
        // Should complete
        let result = timeout(Duration::from_secs(1), rx).await.unwrap().unwrap();
        matches!(result, ShutdownResult::Graceful);
    }
}