use std::collections::{HashMap, BTreeMap, VecDeque};
use std::cmp::Ordering;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

use super::{StreamId, frame::Frame, error::{QuicError, Result}};

/// Priority-based stream scheduler for optimal resource allocation
/// Critical for crypto applications where different data types have different urgency
#[derive(Debug)]
pub struct StreamScheduler {
    /// Streams organized by priority
    priority_queues: BTreeMap<Priority, VecDeque<ScheduledStream>>,
    /// Stream metadata and state
    stream_registry: HashMap<StreamId, StreamMetadata>,
    /// Scheduler configuration
    config: SchedulerConfig,
    /// Bandwidth allocation
    bandwidth_allocator: BandwidthAllocator,
    /// Fairness tracking
    fairness_tracker: FairnessTracker,
    /// Scheduling statistics
    stats: SchedulerStats,
}

#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    /// Enable priority-based scheduling
    pub enable_priority_scheduling: bool,
    /// Enable weighted fair queuing
    pub enable_weighted_fair_queuing: bool,
    /// Enable bandwidth allocation
    pub enable_bandwidth_allocation: bool,
    /// Maximum starvation time for low-priority streams
    pub max_starvation_time: Duration,
    /// Quantum size for round-robin within same priority
    pub quantum_size: usize,
    /// Enable anti-starvation protection
    pub enable_anti_starvation: bool,
    /// Minimum bandwidth guarantee per stream (bytes/sec)
    pub min_bandwidth_guarantee: u64,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            enable_priority_scheduling: true,
            enable_weighted_fair_queuing: true,
            enable_bandwidth_allocation: true,
            max_starvation_time: Duration::from_millis(100),
            quantum_size: 1500, // Typical MTU
            enable_anti_starvation: true,
            min_bandwidth_guarantee: 64 * 1024, // 64 KB/s minimum
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Priority {
    Critical = 0,   // Market data, emergency signals
    High = 1,       // Trading orders, risk management
    Normal = 2,     // Regular application data
    Low = 3,        // Bulk transfers, logs
    Background = 4, // Non-time-sensitive data
}

#[derive(Debug, Clone)]
pub struct StreamMetadata {
    pub stream_id: StreamId,
    pub priority: Priority,
    pub weight: u32,
    pub created_at: Instant,
    pub last_scheduled_at: Option<Instant>,
    pub bytes_sent: u64,
    pub bytes_pending: u64,
    pub bandwidth_allocation: u64, // bytes per second
    pub stream_type: StreamType,
    pub deadlines: Option<StreamDeadline>,
}

#[derive(Debug, Clone)]
pub enum StreamType {
    /// Critical market data streams
    MarketData { symbol: String },
    /// Trading order streams
    Trading { order_type: String },
    /// Risk management streams
    RiskManagement,
    /// General application data
    Application,
    /// Bulk data transfer
    BulkTransfer,
    /// System control streams
    Control,
}

#[derive(Debug, Clone)]
pub struct StreamDeadline {
    /// Hard deadline - data becomes useless after this
    pub hard_deadline: Option<Instant>,
    /// Soft deadline - data loses value after this
    pub soft_deadline: Option<Instant>,
    /// Maximum acceptable latency
    pub max_latency: Option<Duration>,
}

#[derive(Debug)]
struct ScheduledStream {
    stream_id: StreamId,
    priority: Priority,
    weight: u32,
    last_sent: Instant,
    quantum_remaining: usize,
    frames_pending: VecDeque<Frame>,
    bytes_pending: u64,
}

#[derive(Debug)]
struct BandwidthAllocator {
    total_bandwidth: u64,
    allocated_bandwidth: HashMap<StreamId, u64>,
    priority_shares: HashMap<Priority, f64>,
    last_allocation_update: Instant,
}

#[derive(Debug)]
struct FairnessTracker {
    stream_send_times: HashMap<StreamId, VecDeque<Instant>>,
    priority_send_counts: HashMap<Priority, u64>,
    starvation_tracker: HashMap<StreamId, Instant>,
}

#[derive(Debug, Default)]
struct SchedulerStats {
    total_frames_scheduled: u64,
    bytes_scheduled_by_priority: HashMap<Priority, u64>,
    streams_by_priority: HashMap<Priority, usize>,
    starvation_events: u64,
    bandwidth_violations: u64,
    deadline_misses: u64,
    scheduling_decisions: u64,
}

impl StreamScheduler {
    pub fn new(config: SchedulerConfig) -> Self {
        let mut priority_shares = HashMap::new();
        priority_shares.insert(Priority::Critical, 0.4);   // 40% for critical
        priority_shares.insert(Priority::High, 0.3);       // 30% for high
        priority_shares.insert(Priority::Normal, 0.2);     // 20% for normal
        priority_shares.insert(Priority::Low, 0.08);       // 8% for low
        priority_shares.insert(Priority::Background, 0.02); // 2% for background

        Self {
            priority_queues: BTreeMap::new(),
            stream_registry: HashMap::new(),
            config,
            bandwidth_allocator: BandwidthAllocator {
                total_bandwidth: 1_000_000, // 1 MB/s default
                allocated_bandwidth: HashMap::new(),
                priority_shares,
                last_allocation_update: Instant::now(),
            },
            fairness_tracker: FairnessTracker {
                stream_send_times: HashMap::new(),
                priority_send_counts: HashMap::new(),
                starvation_tracker: HashMap::new(),
            },
            stats: SchedulerStats::default(),
        }
    }

    /// Register a new stream with priority and metadata
    pub fn register_stream(
        &mut self,
        stream_id: StreamId,
        priority: Priority,
        weight: u32,
        stream_type: StreamType,
        deadlines: Option<StreamDeadline>,
    ) -> Result<()> {
        let now = Instant::now();
        
        let metadata = StreamMetadata {
            stream_id,
            priority: priority.clone(),
            weight,
            created_at: now,
            last_scheduled_at: None,
            bytes_sent: 0,
            bytes_pending: 0,
            bandwidth_allocation: self.calculate_initial_bandwidth_allocation(&priority, weight),
            stream_type,
            deadlines,
        };

        self.stream_registry.insert(stream_id, metadata);

        // Initialize priority queue if needed
        if !self.priority_queues.contains_key(&priority) {
            self.priority_queues.insert(priority.clone(), VecDeque::new());
        }

        // Update statistics
        *self.stats.streams_by_priority.entry(priority.clone()).or_insert(0) += 1;

        // Initialize starvation tracking
        self.fairness_tracker.starvation_tracker.insert(stream_id, now);

        info!("Registered stream {} with priority {:?} and weight {}", 
              stream_id, priority, weight);

        Ok(())
    }

    /// Add frames to be scheduled for a stream
    pub fn enqueue_frames(&mut self, stream_id: StreamId, frames: Vec<Frame>) -> Result<()> {
        let metadata = self.stream_registry.get_mut(&stream_id)
            .ok_or_else(|| QuicError::Config(format!("Stream {} not registered", stream_id)))?;

        let priority = metadata.priority.clone();
        let weight = metadata.weight;

        // Calculate total bytes and store frame count
        let total_bytes: usize = frames.iter()
            .map(|f| self.frame_size_estimate(f))
            .sum();
        let frame_count = frames.len();

        metadata.bytes_pending += total_bytes as u64;

        // Find or create scheduled stream
        let priority_queue = self.priority_queues.get_mut(&priority)
            .ok_or_else(|| QuicError::Config("Priority queue not found".to_string()))?;

        if let Some(scheduled_stream) = priority_queue.iter_mut()
            .find(|s| s.stream_id == stream_id) {
            // Add frames to existing scheduled stream
            scheduled_stream.frames_pending.extend(frames);
            scheduled_stream.bytes_pending += total_bytes as u64;
        } else {
            // Create new scheduled stream
            let scheduled_stream = ScheduledStream {
                stream_id,
                priority: priority.clone(),
                weight,
                last_sent: Instant::now(),
                quantum_remaining: self.config.quantum_size,
                frames_pending: frames.into_iter().collect(),
                bytes_pending: total_bytes as u64,
            };

            priority_queue.push_back(scheduled_stream);
        }

        debug!("Enqueued {} frames ({} bytes) for stream {} (priority {:?})", 
               frame_count, total_bytes, stream_id, priority);

        Ok(())
    }

    /// Get the next frame to send based on scheduling policy
    pub fn schedule_next_frame(&mut self) -> Option<(StreamId, Frame)> {
        if !self.config.enable_priority_scheduling {
            return self.schedule_round_robin();
        }

        self.stats.scheduling_decisions += 1;
        let now = Instant::now();

        // Check for deadline violations first
        if let Some((stream_id, frame)) = self.schedule_deadline_critical(now) {
            self.update_scheduling_stats(stream_id, &frame, now);
            return Some((stream_id, frame));
        }

        // Anti-starvation check
        if self.config.enable_anti_starvation {
            if let Some((stream_id, frame)) = self.schedule_starved_stream(now) {
                self.update_scheduling_stats(stream_id, &frame, now);
                return Some((stream_id, frame));
            }
        }

        // Priority-based scheduling - collect priority keys first to avoid borrowing issues
        let priority_keys: Vec<Priority> = self.priority_queues.keys().cloned().collect();
        for priority in priority_keys {
            if let Some(queue) = self.priority_queues.get_mut(&priority) {
                if let Some((stream_id, frame)) = self.schedule_from_priority_queue(queue, now) {
                    self.update_scheduling_stats(stream_id, &frame, now);
                    return Some((stream_id, frame));
                }
            }
        }

        None
    }


    /// Schedule frame from a specific priority queue
    fn schedule_from_priority_queue(
        &mut self,
        queue: &mut VecDeque<ScheduledStream>,
        now: Instant,
    ) -> Option<(StreamId, Frame)> {
        if queue.is_empty() {
            return None;
        }

        if self.config.enable_weighted_fair_queuing {
            self.schedule_weighted_fair_direct(queue, now)
        } else {
            self.schedule_round_robin_priority_direct(queue, now)
        }
    }

    /// Weighted fair queuing within priority level (direct access)
    fn schedule_weighted_fair_direct(
        &mut self,
        queue: &mut VecDeque<ScheduledStream>,
        now: Instant,
    ) -> Option<(StreamId, Frame)> {
        // Find stream with highest weight/last_sent ratio
        let mut best_stream_idx = 0;
        let mut best_score = 0.0f64;

        for (idx, stream) in queue.iter().enumerate() {
            if stream.frames_pending.is_empty() {
                continue;
            }

            // Check bandwidth allocation
            if !self.check_bandwidth_allowance(stream.stream_id, now) {
                continue;
            }

            let time_since_last = now.duration_since(stream.last_sent).as_millis() as f64;
            let score = (stream.weight as f64) * time_since_last;

            if score > best_score {
                best_score = score;
                best_stream_idx = idx;
            }
        }

        self.extract_frame_from_stream_direct(queue, best_stream_idx, now)
    }

    /// Weighted fair queuing within priority level
    fn schedule_weighted_fair(
        &mut self,
        queue: &mut VecDeque<ScheduledStream>,
        now: Instant,
    ) -> Option<(StreamId, Frame)> {
        self.schedule_weighted_fair_direct(queue, now)
    }

    /// Round-robin scheduling within priority level (direct access)
    fn schedule_round_robin_priority_direct(
        &mut self,
        queue: &mut VecDeque<ScheduledStream>,
        now: Instant,
    ) -> Option<(StreamId, Frame)> {
        // Find first stream with pending frames and available bandwidth
        for idx in 0..queue.len() {
            if queue[idx].frames_pending.is_empty() {
                continue;
            }

            if !self.check_bandwidth_allowance(queue[idx].stream_id, now) {
                continue;
            }

            return self.extract_frame_from_stream_direct(queue, idx, now);
        }

        None
    }

    /// Round-robin scheduling within priority level
    fn schedule_round_robin_priority(
        &mut self,
        queue: &mut VecDeque<ScheduledStream>,
        now: Instant,
    ) -> Option<(StreamId, Frame)> {
        self.schedule_round_robin_priority_direct(queue, now)
    }

    /// Simple round-robin across all streams (fallback)
    fn schedule_round_robin(&mut self) -> Option<(StreamId, Frame)> {
        let now = Instant::now();
        
        let priority_keys: Vec<Priority> = self.priority_queues.keys().cloned().collect();
        for priority in priority_keys {
            if let Some(queue) = self.priority_queues.get_mut(&priority) {
                if let Some((stream_id, frame)) = self.schedule_round_robin_priority(queue, now) {
                    return Some((stream_id, frame));
                }
            }
        }

        None
    }

    /// Schedule deadline-critical frames
    fn schedule_deadline_critical(&mut self, now: Instant) -> Option<(StreamId, Frame)> {
        let mut critical_streams = Vec::new();

        // Find streams with approaching deadlines
        for (stream_id, metadata) in &self.stream_registry {
            if let Some(ref deadlines) = metadata.deadlines {
                if let Some(hard_deadline) = deadlines.hard_deadline {
                    if hard_deadline <= now + Duration::from_millis(10) { // 10ms grace period
                        critical_streams.push((*stream_id, hard_deadline));
                    }
                } else if let Some(soft_deadline) = deadlines.soft_deadline {
                    if soft_deadline <= now + Duration::from_millis(50) { // 50ms grace period
                        critical_streams.push((*stream_id, soft_deadline));
                    }
                }
            }
        }

        // Sort by deadline urgency
        critical_streams.sort_by(|a, b| a.1.cmp(&b.1));

        // Try to schedule from most urgent stream
        for (stream_id, _deadline) in critical_streams {
            if let Some(metadata) = self.stream_registry.get(&stream_id) {
                let priority = metadata.priority.clone();
                if let Some(queue) = self.priority_queues.get_mut(&priority) {
                    if let Some(stream_idx) = queue.iter().position(|s| s.stream_id == stream_id) {
                        if !queue[stream_idx].frames_pending.is_empty() {
                            self.stats.deadline_misses += 1;
                            return self.extract_frame_from_stream_direct(queue, stream_idx, now);
                        }
                    }
                }
            }
        }

        None
    }

    /// Schedule from starved streams
    fn schedule_starved_stream(&mut self, now: Instant) -> Option<(StreamId, Frame)> {
        let max_starvation = self.config.max_starvation_time;
        let mut starved_streams = Vec::new();

        for (stream_id, last_scheduled) in &self.fairness_tracker.starvation_tracker {
            if now.duration_since(*last_scheduled) > max_starvation {
                starved_streams.push(*stream_id);
            }
        }

        // Try to schedule from starved streams
        for stream_id in starved_streams {
            if let Some(metadata) = self.stream_registry.get(&stream_id) {
                let priority = metadata.priority.clone();
                if let Some(queue) = self.priority_queues.get_mut(&priority) {
                    if let Some(stream_idx) = queue.iter().position(|s| s.stream_id == stream_id) {
                        if !queue[stream_idx].frames_pending.is_empty() {
                            self.stats.starvation_events += 1;
                            info!("Scheduling starved stream {}", stream_id);
                            return self.extract_frame_from_stream_direct(queue, stream_idx, now);
                        }
                    }
                }
            }
        }

        None
    }


    /// Extract frame from stream and update state (direct access)
    fn extract_frame_from_stream_direct(
        &mut self,
        queue: &mut VecDeque<ScheduledStream>,
        stream_idx: usize,
        now: Instant,
    ) -> Option<(StreamId, Frame)> {
        if stream_idx >= queue.len() {
            return None;
        }

        let stream = &mut queue[stream_idx];
        if let Some(frame) = stream.frames_pending.pop_front() {
            let frame_size = self.frame_size_estimate(&frame);
            let stream_id = stream.stream_id;

            // Update stream state
            stream.bytes_pending = stream.bytes_pending.saturating_sub(frame_size as u64);
            stream.last_sent = now;
            stream.quantum_remaining = stream.quantum_remaining.saturating_sub(frame_size);

            // Update metadata
            if let Some(metadata) = self.stream_registry.get_mut(&stream_id) {
                metadata.last_scheduled_at = Some(now);
                metadata.bytes_sent += frame_size as u64;
                metadata.bytes_pending = metadata.bytes_pending.saturating_sub(frame_size as u64);
            }

            // Update fairness tracking
            self.fairness_tracker.starvation_tracker.insert(stream_id, now);

            // If quantum exhausted or no more frames, move to back of queue
            if stream.quantum_remaining == 0 || stream.frames_pending.is_empty() {
                let mut stream = queue.remove(stream_idx).unwrap();
                stream.quantum_remaining = self.config.quantum_size;
                if !stream.frames_pending.is_empty() {
                    queue.push_back(stream);
                }
            }

            return Some((stream_id, frame));
        }

        None
    }

    /// Extract frame from stream and update state
    fn extract_frame_from_stream(
        &mut self,
        queue: &mut VecDeque<ScheduledStream>,
        stream_idx: usize,
        now: Instant,
    ) -> Option<(StreamId, Frame)> {
        self.extract_frame_from_stream_direct(queue, stream_idx, now)
    }

    /// Check if stream has bandwidth allowance
    fn check_bandwidth_allowance(&self, stream_id: StreamId, now: Instant) -> bool {
        if !self.config.enable_bandwidth_allocation {
            return true;
        }

        if let Some(allocation) = self.bandwidth_allocator.allocated_bandwidth.get(&stream_id) {
            if let Some(metadata) = self.stream_registry.get(&stream_id) {
                if let Some(last_scheduled) = metadata.last_scheduled_at {
                    let elapsed = now.duration_since(last_scheduled);
                    let allowed_bytes = (*allocation as f64 * elapsed.as_secs_f64()) as u64;
                    
                    // Allow at least minimum guarantee
                    return allowed_bytes >= self.config.min_bandwidth_guarantee || 
                           elapsed > Duration::from_secs(1);
                }
            }
        }

        true
    }

    /// Update bandwidth allocations
    pub fn update_bandwidth_allocation(&mut self, total_bandwidth: u64) {
        self.bandwidth_allocator.total_bandwidth = total_bandwidth;
        self.bandwidth_allocator.last_allocation_update = Instant::now();

        // Redistribute bandwidth based on priority shares and weights
        let mut total_weight_by_priority: HashMap<Priority, u32> = HashMap::new();

        // Calculate total weights per priority
        for metadata in self.stream_registry.values() {
            *total_weight_by_priority.entry(metadata.priority.clone()).or_insert(0) += metadata.weight;
        }

        // Allocate bandwidth
        for (priority, &share) in &self.bandwidth_allocator.priority_shares {
            let priority_bandwidth = (total_bandwidth as f64 * share) as u64;
            
            if let Some(&total_weight) = total_weight_by_priority.get(priority) {
                if total_weight > 0 {
                    for metadata in self.stream_registry.values_mut() {
                        if metadata.priority == *priority {
                            let stream_allocation = (priority_bandwidth * metadata.weight as u64) / total_weight as u64;
                            metadata.bandwidth_allocation = stream_allocation.max(self.config.min_bandwidth_guarantee);
                            self.bandwidth_allocator.allocated_bandwidth.insert(
                                metadata.stream_id, 
                                metadata.bandwidth_allocation
                            );
                        }
                    }
                }
            }
        }

        debug!("Updated bandwidth allocation: total={} bytes/sec", total_bandwidth);
    }

    /// Calculate initial bandwidth allocation for a stream
    fn calculate_initial_bandwidth_allocation(&self, priority: &Priority, weight: u32) -> u64 {
        let priority_share = self.bandwidth_allocator.priority_shares
            .get(priority)
            .cloned()
            .unwrap_or(0.1);

        let priority_bandwidth = (self.bandwidth_allocator.total_bandwidth as f64 * priority_share) as u64;
        
        // Simple initial allocation based on weight
        let base_allocation = priority_bandwidth / 10; // Assume 10 streams per priority initially
        (base_allocation * weight as u64).max(self.config.min_bandwidth_guarantee)
    }

    /// Estimate frame size for scheduling calculations
    fn frame_size_estimate(&self, frame: &Frame) -> usize {
        match frame {
            Frame::Stream { data, .. } => data.len() + 8, // Add header overhead
            Frame::Crypto { data, .. } => data.len() + 8,
            Frame::Datagram { data } => data.len() + 4,
            _ => 32, // Control frame overhead
        }
    }

    /// Update scheduling statistics
    fn update_scheduling_stats(&mut self, stream_id: StreamId, frame: &Frame, now: Instant) {
        self.stats.total_frames_scheduled += 1;
        
        if let Some(metadata) = self.stream_registry.get(&stream_id) {
            let frame_size = self.frame_size_estimate(frame) as u64;
            *self.stats.bytes_scheduled_by_priority
                .entry(metadata.priority.clone())
                .or_insert(0) += frame_size;
        }

        debug!("Scheduled frame for stream {} at {:?}", stream_id, now);
    }

    /// Remove stream from scheduler
    pub fn unregister_stream(&mut self, stream_id: StreamId) -> Result<()> {
        if let Some(metadata) = self.stream_registry.remove(&stream_id) {
            // Remove from priority queue
            if let Some(queue) = self.priority_queues.get_mut(&metadata.priority) {
                queue.retain(|s| s.stream_id != stream_id);
            }

            // Update statistics
            if let Some(count) = self.stats.streams_by_priority.get_mut(&metadata.priority) {
                *count = count.saturating_sub(1);
            }

            // Cleanup allocations
            self.bandwidth_allocator.allocated_bandwidth.remove(&stream_id);
            self.fairness_tracker.starvation_tracker.remove(&stream_id);
            self.fairness_tracker.stream_send_times.remove(&stream_id);

            info!("Unregistered stream {}", stream_id);
        }

        Ok(())
    }

    /// Get scheduler statistics
    pub fn get_stats(&self) -> &SchedulerStats {
        &self.stats
    }

    /// Get stream metadata
    pub fn get_stream_metadata(&self, stream_id: &StreamId) -> Option<&StreamMetadata> {
        self.stream_registry.get(stream_id)
    }

    /// Update stream priority
    pub fn update_stream_priority(&mut self, stream_id: StreamId, new_priority: Priority) -> Result<()> {
        if let Some(metadata) = self.stream_registry.get_mut(&stream_id) {
            let old_priority = metadata.priority.clone();
            metadata.priority = new_priority.clone();

            // Move stream between priority queues if needed
            if old_priority != new_priority {
                // Remove from old queue
                if let Some(old_queue) = self.priority_queues.get_mut(&old_priority) {
                    if let Some(pos) = old_queue.iter().position(|s| s.stream_id == stream_id) {
                        let mut scheduled_stream = old_queue.remove(pos).unwrap();
                        scheduled_stream.priority = new_priority.clone();

                        // Add to new queue
                        let new_queue = self.priority_queues.entry(new_priority.clone()).or_insert_with(VecDeque::new);
                        new_queue.push_back(scheduled_stream);
                    }
                }

                // Update statistics
                if let Some(count) = self.stats.streams_by_priority.get_mut(&old_priority) {
                    *count = count.saturating_sub(1);
                }
                *self.stats.streams_by_priority.entry(new_priority).or_insert(0) += 1;

                info!("Updated stream {} priority: {:?} -> {:?}", stream_id, old_priority, metadata.priority);
            }

            Ok(())
        } else {
            Err(QuicError::Config(format!("Stream {} not found", stream_id)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn test_stream_registration() {
        let mut scheduler = StreamScheduler::new(SchedulerConfig::default());
        let stream_id = StreamId::new(0);
        
        scheduler.register_stream(
            stream_id,
            Priority::High,
            10,
            StreamType::Trading { order_type: "market".to_string() },
            None,
        ).unwrap();

        assert!(scheduler.stream_registry.contains_key(&stream_id));
        assert_eq!(scheduler.stats.streams_by_priority[&Priority::High], 1);
    }

    #[test]
    fn test_priority_scheduling() {
        let mut scheduler = StreamScheduler::new(SchedulerConfig::default());
        
        let stream1 = StreamId::new(1);
        let stream2 = StreamId::new(2);
        
        scheduler.register_stream(
            stream1, Priority::Low, 1, StreamType::Application, None
        ).unwrap();
        
        scheduler.register_stream(
            stream2, Priority::Critical, 1, StreamType::MarketData { symbol: "BTC".to_string() }, None
        ).unwrap();

        // Add frames
        let frames1 = vec![Frame::Stream {
            stream_id: stream1,
            offset: 0,
            data: Bytes::from("low priority"),
            fin: false,
        }];
        
        let frames2 = vec![Frame::Stream {
            stream_id: stream2,
            offset: 0,
            data: Bytes::from("critical data"),
            fin: false,
        }];

        scheduler.enqueue_frames(stream1, frames1).unwrap();
        scheduler.enqueue_frames(stream2, frames2).unwrap();

        // Should schedule critical first
        let (scheduled_stream, _frame) = scheduler.schedule_next_frame().unwrap();
        assert_eq!(scheduled_stream, stream2);
    }

    #[test]
    fn test_bandwidth_allocation() {
        let mut scheduler = StreamScheduler::new(SchedulerConfig::default());
        
        let stream_id = StreamId::new(0);
        scheduler.register_stream(
            stream_id, Priority::High, 5, StreamType::Application, None
        ).unwrap();

        scheduler.update_bandwidth_allocation(1_000_000); // 1 MB/s

        let metadata = scheduler.get_stream_metadata(&stream_id).unwrap();
        assert!(metadata.bandwidth_allocation > 0);
    }
}