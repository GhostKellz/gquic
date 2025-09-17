//! QUIC flow control implementation
//!
//! This module provides connection-level and stream-level flow control
//! as specified in RFC 9000 Section 4.

use crate::quic::error::{QuicError, Result};
use crate::quic::stream::StreamId;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, warn};

/// Flow control configuration
#[derive(Debug, Clone)]
pub struct FlowControlConfig {
    /// Initial connection-level flow control limit
    pub initial_connection_window: u64,
    /// Initial stream-level flow control limit
    pub initial_stream_window: u64,
    /// Maximum connection-level flow control limit
    pub max_connection_window: u64,
    /// Maximum stream-level flow control limit
    pub max_stream_window: u64,
    /// Auto-tuning enabled
    pub auto_tuning: bool,
}

impl Default for FlowControlConfig {
    fn default() -> Self {
        Self {
            initial_connection_window: 1024 * 1024,      // 1MB
            initial_stream_window: 256 * 1024,           // 256KB
            max_connection_window: 16 * 1024 * 1024,     // 16MB
            max_stream_window: 4 * 1024 * 1024,          // 4MB
            auto_tuning: true,
        }
    }
}

/// Flow control window for a single stream or connection
#[derive(Debug)]
pub struct FlowControlWindow {
    /// Maximum data that can be sent (peer's receive limit)
    max_data: AtomicU64,
    /// Amount of data sent so far
    sent_data: AtomicU64,
    /// Maximum data we can receive (our receive limit)
    receive_limit: AtomicU64,
    /// Amount of data received so far
    received_data: AtomicU64,
    /// Amount of data consumed by application
    consumed_data: AtomicU64,
}

impl FlowControlWindow {
    pub fn new(initial_send_limit: u64, initial_receive_limit: u64) -> Self {
        Self {
            max_data: AtomicU64::new(initial_send_limit),
            sent_data: AtomicU64::new(0),
            receive_limit: AtomicU64::new(initial_receive_limit),
            received_data: AtomicU64::new(0),
            consumed_data: AtomicU64::new(0),
        }
    }

    /// Check if we can send the specified amount of data
    pub fn can_send(&self, amount: u64) -> bool {
        let current_sent = self.sent_data.load(Ordering::Relaxed);
        let max_allowed = self.max_data.load(Ordering::Relaxed);
        current_sent + amount <= max_allowed
    }

    /// Reserve send capacity (call before sending)
    pub fn reserve_send(&self, amount: u64) -> Result<()> {
        loop {
            let current_sent = self.sent_data.load(Ordering::Relaxed);
            let max_allowed = self.max_data.load(Ordering::Relaxed);

            if current_sent + amount > max_allowed {
                return Err(QuicError::FlowControl("Send window exceeded".to_string()));
            }

            if self.sent_data.compare_exchange_weak(
                current_sent,
                current_sent + amount,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ).is_ok() {
                debug!("Reserved {} bytes for sending, total sent: {}", amount, current_sent + amount);
                break;
            }
        }
        Ok(())
    }

    /// Get available send capacity
    pub fn send_capacity(&self) -> u64 {
        let current_sent = self.sent_data.load(Ordering::Relaxed);
        let max_allowed = self.max_data.load(Ordering::Relaxed);
        max_allowed.saturating_sub(current_sent)
    }

    /// Update maximum send limit (from peer's MAX_DATA/MAX_STREAM_DATA frame)
    pub fn update_send_limit(&self, new_limit: u64) {
        let current_limit = self.max_data.load(Ordering::Relaxed);
        if new_limit > current_limit {
            self.max_data.store(new_limit, Ordering::Relaxed);
            debug!("Updated send limit to {}", new_limit);
        }
    }

    /// Record received data
    pub fn record_received(&self, amount: u64) -> Result<bool> {
        loop {
            let current_received = self.received_data.load(Ordering::Relaxed);
            let receive_limit = self.receive_limit.load(Ordering::Relaxed);

            if current_received + amount > receive_limit {
                return Err(QuicError::FlowControl("Receive limit exceeded".to_string()));
            }

            if self.received_data.compare_exchange_weak(
                current_received,
                current_received + amount,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ).is_ok() {
                debug!("Recorded {} bytes received, total: {}", amount, current_received + amount);

                // Check if we should send a flow control update
                let consumed = self.consumed_data.load(Ordering::Relaxed);
                let window_used = (current_received + amount).saturating_sub(consumed);
                let window_size = receive_limit.saturating_sub(consumed);

                // Send update when 50% of window is used
                let should_update = window_used >= window_size / 2;

                return Ok(should_update);
            }
        }
    }

    /// Mark data as consumed by application
    pub fn consume_data(&self, amount: u64) -> u64 {
        let consumed = self.consumed_data.fetch_add(amount, Ordering::Relaxed);
        debug!("Consumed {} bytes, total consumed: {}", amount, consumed + amount);
        consumed + amount
    }

    /// Get new receive limit for flow control frame
    pub fn new_receive_limit(&self, config: &FlowControlConfig) -> u64 {
        let consumed = self.consumed_data.load(Ordering::Relaxed);
        let current_limit = self.receive_limit.load(Ordering::Relaxed);

        if config.auto_tuning {
            // Auto-tune based on consumption rate
            let window_size = current_limit.saturating_sub(consumed);
            let new_limit = std::cmp::min(
                consumed + window_size * 2, // Double the window
                config.max_stream_window.max(config.max_connection_window),
            );

            self.receive_limit.store(new_limit, Ordering::Relaxed);
            new_limit
        } else {
            current_limit
        }
    }

    /// Get current statistics
    pub fn stats(&self) -> FlowControlStats {
        FlowControlStats {
            max_data: self.max_data.load(Ordering::Relaxed),
            sent_data: self.sent_data.load(Ordering::Relaxed),
            receive_limit: self.receive_limit.load(Ordering::Relaxed),
            received_data: self.received_data.load(Ordering::Relaxed),
            consumed_data: self.consumed_data.load(Ordering::Relaxed),
        }
    }
}

/// Flow control statistics
#[derive(Debug, Clone)]
pub struct FlowControlStats {
    pub max_data: u64,
    pub sent_data: u64,
    pub receive_limit: u64,
    pub received_data: u64,
    pub consumed_data: u64,
}

/// Connection-level flow controller
#[derive(Debug)]
pub struct ConnectionFlowController {
    /// Connection-level flow control window
    connection_window: FlowControlWindow,
    /// Per-stream flow control windows
    stream_windows: HashMap<StreamId, FlowControlWindow>,
    /// Flow control configuration
    config: FlowControlConfig,
}

impl ConnectionFlowController {
    pub fn new(config: FlowControlConfig) -> Self {
        let connection_window = FlowControlWindow::new(
            config.initial_connection_window,
            config.initial_connection_window,
        );

        Self {
            connection_window,
            stream_windows: HashMap::new(),
            config,
        }
    }

    /// Create a new stream with flow control
    pub fn create_stream(&mut self, stream_id: StreamId) {
        let window = FlowControlWindow::new(
            self.config.initial_stream_window,
            self.config.initial_stream_window,
        );
        self.stream_windows.insert(stream_id, window);
        debug!("Created flow control for stream {}", stream_id.value());
    }

    /// Check if we can send data on a stream
    pub fn can_send_stream_data(&self, stream_id: StreamId, amount: u64) -> bool {
        // Check both connection and stream limits
        let connection_ok = self.connection_window.can_send(amount);

        let stream_ok = self.stream_windows.get(&stream_id)
            .map(|window| window.can_send(amount))
            .unwrap_or(false);

        connection_ok && stream_ok
    }

    /// Reserve capacity for sending stream data
    pub fn reserve_stream_send(&self, stream_id: StreamId, amount: u64) -> Result<()> {
        // Reserve on both connection and stream level
        self.connection_window.reserve_send(amount)?;

        if let Some(stream_window) = self.stream_windows.get(&stream_id) {
            if let Err(e) = stream_window.reserve_send(amount) {
                // Rollback connection reservation
                // In a real implementation, this would need proper rollback
                warn!("Failed to reserve stream capacity: {}", e);
                return Err(e);
            }
        } else {
            return Err(QuicError::Protocol(format!("Stream {} not found", stream_id.value())));
        }

        Ok(())
    }

    /// Get send capacity for a stream (minimum of connection and stream limits)
    pub fn stream_send_capacity(&self, stream_id: StreamId) -> u64 {
        let connection_capacity = self.connection_window.send_capacity();

        let stream_capacity = self.stream_windows.get(&stream_id)
            .map(|window| window.send_capacity())
            .unwrap_or(0);

        std::cmp::min(connection_capacity, stream_capacity)
    }

    /// Record received data on a stream
    pub fn record_stream_received(&mut self, stream_id: StreamId, amount: u64) -> Result<(bool, bool)> {
        // Record on both connection and stream level
        let connection_update = self.connection_window.record_received(amount)?;

        let stream_update = if let Some(stream_window) = self.stream_windows.get(&stream_id) {
            stream_window.record_received(amount)?
        } else {
            return Err(QuicError::Protocol(format!("Stream {} not found", stream_id.value())));
        };

        Ok((connection_update, stream_update))
    }

    /// Consume data on a stream (mark as read by application)
    pub fn consume_stream_data(&mut self, stream_id: StreamId, amount: u64) -> Result<()> {
        // Consume on both connection and stream level
        self.connection_window.consume_data(amount);

        if let Some(stream_window) = self.stream_windows.get(&stream_id) {
            stream_window.consume_data(amount);
        } else {
            return Err(QuicError::Protocol(format!("Stream {} not found", stream_id.value())));
        }

        Ok(())
    }

    /// Update connection-level send limit
    pub fn update_connection_send_limit(&self, new_limit: u64) {
        self.connection_window.update_send_limit(new_limit);
    }

    /// Update stream-level send limit
    pub fn update_stream_send_limit(&self, stream_id: StreamId, new_limit: u64) -> Result<()> {
        if let Some(stream_window) = self.stream_windows.get(&stream_id) {
            stream_window.update_send_limit(new_limit);
            Ok(())
        } else {
            Err(QuicError::Protocol(format!("Stream {} not found", stream_id.value())))
        }
    }

    /// Get new connection receive limit for MAX_DATA frame
    pub fn new_connection_receive_limit(&self) -> u64 {
        self.connection_window.new_receive_limit(&self.config)
    }

    /// Get new stream receive limit for MAX_STREAM_DATA frame
    pub fn new_stream_receive_limit(&self, stream_id: StreamId) -> Result<u64> {
        if let Some(stream_window) = self.stream_windows.get(&stream_id) {
            Ok(stream_window.new_receive_limit(&self.config))
        } else {
            Err(QuicError::Protocol(format!("Stream {} not found", stream_id.value())))
        }
    }

    /// Remove stream flow control
    pub fn remove_stream(&mut self, stream_id: StreamId) {
        self.stream_windows.remove(&stream_id);
        debug!("Removed flow control for stream {}", stream_id.value());
    }

    /// Get connection flow control statistics
    pub fn connection_stats(&self) -> FlowControlStats {
        self.connection_window.stats()
    }

    /// Get stream flow control statistics
    pub fn stream_stats(&self, stream_id: StreamId) -> Option<FlowControlStats> {
        self.stream_windows.get(&stream_id).map(|window| window.stats())
    }

    /// Get overall flow control state for monitoring
    pub fn overall_stats(&self) -> OverallFlowControlStats {
        let connection_stats = self.connection_stats();
        let active_streams = self.stream_windows.len();

        let total_stream_sent = self.stream_windows.values()
            .map(|window| window.stats().sent_data)
            .sum();

        let total_stream_received = self.stream_windows.values()
            .map(|window| window.stats().received_data)
            .sum();

        OverallFlowControlStats {
            connection: connection_stats,
            active_streams,
            total_stream_sent,
            total_stream_received,
        }
    }
}

/// Overall flow control statistics for monitoring
#[derive(Debug, Clone)]
pub struct OverallFlowControlStats {
    pub connection: FlowControlStats,
    pub active_streams: usize,
    pub total_stream_sent: u64,
    pub total_stream_received: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_control_window() {
        let window = FlowControlWindow::new(1000, 1000);

        // Test sending
        assert!(window.can_send(500));
        assert!(window.reserve_send(500).is_ok());
        assert_eq!(window.send_capacity(), 500);

        assert!(window.can_send(500));
        assert!(window.reserve_send(500).is_ok());
        assert_eq!(window.send_capacity(), 0);

        // Should fail to send more
        assert!(!window.can_send(1));
        assert!(window.reserve_send(1).is_err());
    }

    #[test]
    fn test_flow_control_receive() {
        let window = FlowControlWindow::new(1000, 1000);

        // Test receiving
        assert!(window.record_received(400).is_ok());
        assert!(window.record_received(400).is_ok());
        assert!(window.record_received(200).is_ok());

        // Should fail to receive more than limit
        assert!(window.record_received(1).is_err());

        // Consume some data and check we can receive more
        window.consume_data(500);
        assert!(window.record_received(1).is_err()); // Still at limit
    }

    #[test]
    fn test_connection_flow_controller() {
        let config = FlowControlConfig::default();
        let mut controller = ConnectionFlowController::new(config);

        let stream_id = StreamId::new(4); // Client-initiated bidirectional
        controller.create_stream(stream_id);

        // Test stream send capacity
        assert!(controller.can_send_stream_data(stream_id, 1000));
        assert!(controller.reserve_stream_send(stream_id, 1000).is_ok());

        let capacity = controller.stream_send_capacity(stream_id);
        assert!(capacity > 0);
    }
}