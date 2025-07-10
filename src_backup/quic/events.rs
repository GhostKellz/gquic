use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::{broadcast, mpsc, RwLock, Mutex};
use serde::{Serialize, Deserialize};
use tracing::{debug, info, warn, error};

use super::{ConnectionId, StreamId, frame::Frame, error::{QuicError, Result}};

/// Connection-level event system for monitoring and automation
/// Essential for crypto applications requiring real-time monitoring and response
#[derive(Debug)]
pub struct EventManager {
    /// Event subscribers by type
    subscribers: Arc<RwLock<HashMap<EventType, Vec<EventSubscriber>>>>,
    /// Event history for analysis
    event_history: Arc<RwLock<VecDeque<EventRecord>>>,
    /// Event configuration
    config: EventConfig,
    /// Event statistics
    stats: Arc<Mutex<EventStats>>,
    /// Connection-specific event state
    connection_state: Arc<RwLock<HashMap<ConnectionId, ConnectionEventState>>>,
}

#[derive(Debug, Clone)]
pub struct EventConfig {
    /// Enable event system
    pub enable_events: bool,
    /// Maximum event history size
    pub max_history_size: usize,
    /// Event retention duration
    pub retention_duration: Duration,
    /// Enable event aggregation
    pub enable_aggregation: bool,
    /// Aggregation window
    pub aggregation_window: Duration,
    /// Enable event filtering
    pub enable_filtering: bool,
    /// Event priority threshold
    pub priority_threshold: EventPriority,
}

impl Default for EventConfig {
    fn default() -> Self {
        Self {
            enable_events: true,
            max_history_size: 10000,
            retention_duration: Duration::from_secs(3600), // 1 hour
            enable_aggregation: true,
            aggregation_window: Duration::from_secs(60), // 1 minute
            enable_filtering: true,
            priority_threshold: EventPriority::Low,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventType {
    // Connection events
    ConnectionEstablished,
    ConnectionClosed,
    ConnectionError,
    ConnectionMigrated,
    ConnectionTimeout,
    
    // Stream events
    StreamOpened,
    StreamClosed,
    StreamReset,
    StreamDataSent,
    StreamDataReceived,
    
    // Protocol events
    HandshakeCompleted,
    HandshakeFailed,
    PacketSent,
    PacketReceived,
    PacketLost,
    PacketAcknowledged,
    
    // Crypto events
    KeyUpdate,
    CryptoError,
    ZeroRttAccepted,
    ZeroRttRejected,
    
    // Performance events
    CongestionDetected,
    BandwidthChanged,
    RttChanged,
    LossDetected,
    
    // Security events
    SecurityViolation,
    DdosDetected,
    RateLimitExceeded,
    ConnectionIdRotated,
    
    // Application events
    ApplicationError,
    Custom(String),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EventPriority {
    Critical = 0,
    High = 1,
    Medium = 2,
    Low = 3,
    Debug = 4,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: u64,
    pub event_type: EventType,
    pub priority: EventPriority,
    pub timestamp: SystemTime,
    pub connection_id: Option<ConnectionId>,
    pub stream_id: Option<StreamId>,
    pub data: EventData,
    pub correlation_id: Option<String>,
    pub tags: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventData {
    ConnectionEstablished {
        peer_address: String,
        alpn_protocol: Option<String>,
        server_name: Option<String>,
    },
    ConnectionClosed {
        reason: String,
        error_code: Option<u64>,
        bytes_sent: u64,
        bytes_received: u64,
        duration: Duration,
    },
    StreamData {
        bytes: u64,
        offset: u64,
        fin: bool,
    },
    PacketInfo {
        packet_number: u64,
        size: usize,
        packet_type: String,
    },
    PerformanceMetric {
        metric_name: String,
        value: f64,
        unit: String,
    },
    SecurityAlert {
        alert_type: String,
        severity: String,
        details: String,
    },
    Custom {
        data: serde_json::Value,
    },
    Empty,
}

#[derive(Debug)]
struct EventRecord {
    event: Event,
    received_at: Instant,
}

#[derive(Debug, Clone)]
struct EventSubscriber {
    id: String,
    sender: mpsc::UnboundedSender<Event>,
    filter: Option<EventFilter>,
    subscription_time: Instant,
}

#[derive(Debug, Clone)]
pub struct EventFilter {
    pub connection_ids: Option<Vec<ConnectionId>>,
    pub event_types: Option<Vec<EventType>>,
    pub min_priority: Option<EventPriority>,
    pub tags: Option<HashMap<String, String>>,
    pub custom_filter: Option<String>,
}

#[derive(Debug)]
struct ConnectionEventState {
    connection_id: ConnectionId,
    event_count: HashMap<EventType, u64>,
    last_event_time: HashMap<EventType, Instant>,
    aggregated_events: VecDeque<AggregatedEvent>,
}

#[derive(Debug, Clone)]
struct AggregatedEvent {
    event_type: EventType,
    count: u64,
    first_timestamp: SystemTime,
    last_timestamp: SystemTime,
    aggregated_data: Option<serde_json::Value>,
}

#[derive(Debug, Default, Clone)]
struct EventStats {
    total_events_generated: u64,
    events_by_type: HashMap<EventType, u64>,
    events_by_priority: HashMap<EventPriority, u64>,
    subscribers_count: usize,
    dropped_events: u64,
    filtered_events: u64,
}

impl EventManager {
    pub fn new(config: EventConfig) -> Self {
        Self {
            subscribers: Arc::new(RwLock::new(HashMap::new())),
            event_history: Arc::new(RwLock::new(VecDeque::new())),
            config,
            stats: Arc::new(Mutex::new(EventStats::default())),
            connection_state: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Emit an event
    pub async fn emit_event(&self, event: Event) -> Result<()> {
        if !self.config.enable_events {
            return Ok(());
        }

        // Apply filtering
        if self.config.enable_filtering && !self.should_process_event(&event).await {
            let mut stats = self.stats.lock().await;
            stats.filtered_events += 1;
            return Ok(());
        }

        let now = Instant::now();

        // Update connection state
        if let Some(connection_id) = event.connection_id {
            self.update_connection_state(connection_id, &event, now).await;
        }

        // Add to history
        let event_record = EventRecord {
            event: event.clone(),
            received_at: now,
        };

        let mut history = self.event_history.write().await;
        history.push_back(event_record);

        // Maintain history size
        if history.len() > self.config.max_history_size {
            history.pop_front();
        }
        drop(history);

        // Distribute to subscribers
        self.distribute_event(event.clone()).await?;

        // Update statistics
        let mut stats = self.stats.lock().await;
        stats.total_events_generated += 1;
        *stats.events_by_type.entry(event.event_type.clone()).or_insert(0) += 1;
        *stats.events_by_priority.entry(event.priority.clone()).or_insert(0) += 1;

        debug!("Emitted event: {:?} (ID: {})", event.event_type, event.id);

        Ok(())
    }

    /// Subscribe to events
    pub async fn subscribe(
        &self,
        subscriber_id: String,
        event_types: Vec<EventType>,
        filter: Option<EventFilter>,
    ) -> Result<mpsc::UnboundedReceiver<Event>> {
        let (tx, rx) = mpsc::unbounded_channel();

        let subscriber = EventSubscriber {
            id: subscriber_id.clone(),
            sender: tx,
            filter,
            subscription_time: Instant::now(),
        };

        let mut subscribers = self.subscribers.write().await;
        for event_type in event_types {
            subscribers.entry(event_type).or_insert_with(Vec::new).push(subscriber.clone());
        }

        // Update stats
        let mut stats = self.stats.lock().await;
        stats.subscribers_count = subscribers.values().map(|v| v.len()).sum();

        info!("Added event subscriber: {}", subscriber_id);

        Ok(rx)
    }

    /// Unsubscribe from events
    pub async fn unsubscribe(&self, subscriber_id: &str) -> Result<()> {
        let mut subscribers = self.subscribers.write().await;
        
        for event_subscribers in subscribers.values_mut() {
            event_subscribers.retain(|s| s.id != subscriber_id);
        }

        // Update stats
        let mut stats = self.stats.lock().await;
        stats.subscribers_count = subscribers.values().map(|v| v.len()).sum();

        info!("Removed event subscriber: {}", subscriber_id);

        Ok(())
    }

    /// Distribute event to subscribers
    async fn distribute_event(&self, event: Event) -> Result<()> {
        let subscribers = self.subscribers.read().await;
        
        if let Some(event_subscribers) = subscribers.get(&event.event_type) {
            for subscriber in event_subscribers {
                // Apply subscriber filter
                if self.subscriber_filter_matches(&event, &subscriber.filter) {
                    if let Err(_) = subscriber.sender.send(event.clone()) {
                        warn!("Failed to deliver event to subscriber: {}", subscriber.id);
                        // Subscriber channel is closed, should clean up
                    }
                }
            }
        }

        Ok(())
    }

    /// Check if event should be processed
    async fn should_process_event(&self, event: &Event) -> bool {
        // Priority check
        if event.priority > self.config.priority_threshold {
            return false;
        }

        // Additional filtering logic can be added here
        true
    }

    /// Check if subscriber filter matches event
    fn subscriber_filter_matches(&self, event: &Event, filter: &Option<EventFilter>) -> bool {
        if let Some(filter) = filter {
            // Connection ID filter
            if let Some(ref connection_ids) = filter.connection_ids {
                if let Some(event_conn_id) = &event.connection_id {
                    if !connection_ids.contains(&event_conn_id) {
                        return false;
                    }
                } else {
                    return false; // Event has no connection ID but filter requires one
                }
            }

            // Event type filter
            if let Some(ref event_types) = filter.event_types {
                if !event_types.contains(&event.event_type) {
                    return false;
                }
            }

            // Priority filter
            if let Some(ref min_priority) = filter.min_priority {
                if event.priority > *min_priority {
                    return false;
                }
            }

            // Tag filter
            if let Some(ref filter_tags) = filter.tags {
                for (key, value) in filter_tags {
                    if event.tags.get(key) != Some(value) {
                        return false;
                    }
                }
            }
        }

        true
    }

    /// Update connection state with event
    async fn update_connection_state(&self, connection_id: ConnectionId, event: &Event, now: Instant) {
        let mut connection_states = self.connection_state.write().await;
        
        let state = connection_states.entry(connection_id.clone()).or_insert_with(|| {
            ConnectionEventState {
                connection_id,
                event_count: HashMap::new(),
                last_event_time: HashMap::new(),
                aggregated_events: VecDeque::new(),
            }
        });

        // Update event count
        *state.event_count.entry(event.event_type.clone()).or_insert(0) += 1;
        state.last_event_time.insert(event.event_type.clone(), now);

        // Handle aggregation
        if self.config.enable_aggregation {
            self.update_aggregated_events(state, event, now);
        }
    }

    /// Update aggregated events
    fn update_aggregated_events(&self, state: &mut ConnectionEventState, event: &Event, now: Instant) {
        let window_start = now - self.config.aggregation_window;

        // Remove old aggregated events
        state.aggregated_events.retain(|agg| {
            SystemTime::now().duration_since(agg.first_timestamp).unwrap_or(Duration::ZERO) 
                < self.config.aggregation_window
        });

        // Find existing aggregation or create new one
        if let Some(existing) = state.aggregated_events.iter_mut()
            .find(|agg| agg.event_type == event.event_type) {
            existing.count += 1;
            existing.last_timestamp = event.timestamp;
        } else {
            let aggregated = AggregatedEvent {
                event_type: event.event_type.clone(),
                count: 1,
                first_timestamp: event.timestamp,
                last_timestamp: event.timestamp,
                aggregated_data: None,
            };
            state.aggregated_events.push_back(aggregated);
        }
    }

    /// Get event history
    pub async fn get_event_history(
        &self,
        filter: Option<EventFilter>,
        limit: Option<usize>,
    ) -> Vec<Event> {
        let history = self.event_history.read().await;
        
        let mut events: Vec<Event> = history.iter()
            .filter(|record| {
                if let Some(ref filter) = filter {
                    self.subscriber_filter_matches(&record.event, &Some(filter.clone()))
                } else {
                    true
                }
            })
            .map(|record| record.event.clone())
            .collect();

        if let Some(limit) = limit {
            events.truncate(limit);
        }

        events
    }

    /// Get connection event statistics
    pub async fn get_connection_stats(&self, connection_id: ConnectionId) -> Option<HashMap<EventType, u64>> {
        let connection_states = self.connection_state.read().await;
        connection_states.get(&connection_id).map(|state| state.event_count.clone())
    }

    /// Clean up old events and state
    pub async fn cleanup_old_data(&self) {
        let now = SystemTime::now();
        let cutoff = now - self.config.retention_duration;

        // Clean up event history
        {
            let mut history = self.event_history.write().await;
            history.retain(|record| record.event.timestamp > cutoff);
        }

        // Clean up connection states
        {
            let mut connection_states = self.connection_state.write().await;
            connection_states.retain(|_, state| {
                state.last_event_time.values().any(|&time| {
                    let now_secs = now.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as i64;
                    let time_secs = time.elapsed().as_secs() as i64;
                    let retention_secs = self.config.retention_duration.as_secs() as i64;
                    (now_secs - time_secs) < retention_secs
                })
            });
        }

        debug!("Cleaned up old event data");
    }

    /// Get event statistics
    pub async fn get_stats(&self) -> EventStats {
        self.stats.lock().await.clone()
    }

    /// Create a connection established event
    pub fn create_connection_established_event(
        &self,
        connection_id: ConnectionId,
        peer_address: String,
        alpn_protocol: Option<String>,
        server_name: Option<String>,
    ) -> Event {
        Event {
            id: self.generate_event_id(),
            event_type: EventType::ConnectionEstablished,
            priority: EventPriority::Medium,
            timestamp: SystemTime::now(),
            connection_id: Some(connection_id),
            stream_id: None,
            data: EventData::ConnectionEstablished {
                peer_address,
                alpn_protocol,
                server_name,
            },
            correlation_id: None,
            tags: HashMap::new(),
        }
    }

    /// Create a performance metric event
    pub fn create_performance_event(
        &self,
        connection_id: ConnectionId,
        metric_name: String,
        value: f64,
        unit: String,
    ) -> Event {
        Event {
            id: self.generate_event_id(),
            event_type: EventType::BandwidthChanged,
            priority: EventPriority::Low,
            timestamp: SystemTime::now(),
            connection_id: Some(connection_id),
            stream_id: None,
            data: EventData::PerformanceMetric {
                metric_name,
                value,
                unit,
            },
            correlation_id: None,
            tags: HashMap::new(),
        }
    }

    /// Create a security alert event
    pub fn create_security_event(
        &self,
        connection_id: Option<ConnectionId>,
        alert_type: String,
        severity: String,
        details: String,
    ) -> Event {
        Event {
            id: self.generate_event_id(),
            event_type: EventType::SecurityViolation,
            priority: EventPriority::Critical,
            timestamp: SystemTime::now(),
            connection_id,
            stream_id: None,
            data: EventData::SecurityAlert {
                alert_type,
                severity,
                details,
            },
            correlation_id: None,
            tags: HashMap::new(),
        }
    }

    /// Generate unique event ID
    fn generate_event_id(&self) -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        COUNTER.fetch_add(1, Ordering::Relaxed)
    }
}

/// Event-driven automation system
#[derive(Debug)]
pub struct EventAutomation {
    event_manager: Arc<EventManager>,
    automation_rules: Arc<RwLock<Vec<AutomationRule>>>,
    action_executor: ActionExecutor,
}

#[derive(Debug, Clone)]
pub struct AutomationRule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub trigger: EventTrigger,
    pub actions: Vec<AutomationAction>,
    pub cooldown: Duration,
    pub last_triggered: Option<Instant>,
}

#[derive(Debug, Clone)]
pub enum EventTrigger {
    SingleEvent {
        event_type: EventType,
        condition: Option<String>,
    },
    EventSequence {
        events: Vec<EventType>,
        within: Duration,
    },
    EventCount {
        event_type: EventType,
        count: u64,
        within: Duration,
    },
    MetricThreshold {
        metric_name: String,
        threshold: f64,
        comparison: ThresholdComparison,
    },
}

#[derive(Debug, Clone)]
pub enum ThresholdComparison {
    GreaterThan,
    LessThan,
    Equal,
}

#[derive(Debug, Clone)]
pub enum AutomationAction {
    Log {
        level: String,
        message: String,
    },
    SendAlert {
        recipient: String,
        message: String,
    },
    TriggerConnectionMigration {
        connection_id: ConnectionId,
    },
    AdjustCongestionControl {
        connection_id: ConnectionId,
        algorithm: String,
    },
    ForceConnectionClose {
        connection_id: ConnectionId,
        reason: String,
    },
    Custom {
        action_type: String,
        parameters: HashMap<String, String>,
    },
}

#[derive(Debug)]
struct ActionExecutor {
    pending_actions: Arc<Mutex<VecDeque<(AutomationAction, Instant)>>>,
}

impl EventAutomation {
    pub fn new(event_manager: Arc<EventManager>) -> Self {
        Self {
            event_manager,
            automation_rules: Arc::new(RwLock::new(Vec::new())),
            action_executor: ActionExecutor {
                pending_actions: Arc::new(Mutex::new(VecDeque::new())),
            },
        }
    }

    /// Add automation rule
    pub async fn add_rule(&self, rule: AutomationRule) {
        let mut rules = self.automation_rules.write().await;
        rules.push(rule);
        info!("Added automation rule: {}", rules.last().unwrap().name);
    }

    /// Process event for automation
    pub async fn process_event(&self, event: &Event) -> Result<()> {
        let mut rules = self.automation_rules.write().await;
        let now = Instant::now();

        for rule in rules.iter_mut() {
            if !rule.enabled {
                continue;
            }

            // Check cooldown
            if let Some(last_triggered) = rule.last_triggered {
                if now.duration_since(last_triggered) < rule.cooldown {
                    continue;
                }
            }

            // Check trigger
            if self.check_trigger(&rule.trigger, event).await {
                rule.last_triggered = Some(now);
                
                // Execute actions
                for action in &rule.actions {
                    self.action_executor.execute_action(action.clone(), now).await?;
                }

                info!("Triggered automation rule: {}", rule.name);
            }
        }

        Ok(())
    }

    /// Check if trigger condition is met
    async fn check_trigger(&self, trigger: &EventTrigger, event: &Event) -> bool {
        match trigger {
            EventTrigger::SingleEvent { event_type, condition: _ } => {
                event.event_type == *event_type
            }
            EventTrigger::EventCount { event_type, count, within } => {
                if event.event_type != *event_type {
                    return false;
                }

                // Check event count within time window
                let cutoff = SystemTime::now() - *within;
                let history = self.event_manager.get_event_history(
                    Some(EventFilter {
                        connection_ids: event.connection_id.map(|id| vec![id]),
                        event_types: Some(vec![event_type.clone()]),
                        min_priority: None,
                        tags: None,
                        custom_filter: None,
                    }),
                    None,
                ).await;

                let recent_count = history.iter()
                    .filter(|e| e.timestamp > cutoff)
                    .count() as u64;

                recent_count >= *count
            }
            EventTrigger::MetricThreshold { metric_name, threshold, comparison } => {
                if let EventData::PerformanceMetric { metric_name: event_metric, value, .. } = &event.data {
                    if event_metric == metric_name {
                        match comparison {
                            ThresholdComparison::GreaterThan => *value > *threshold,
                            ThresholdComparison::LessThan => *value < *threshold,
                            ThresholdComparison::Equal => (*value - *threshold).abs() < f64::EPSILON,
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            _ => false, // TODO: Implement other trigger types
        }
    }
}

impl ActionExecutor {
    async fn execute_action(&self, action: AutomationAction, timestamp: Instant) -> Result<()> {
        let mut pending = self.pending_actions.lock().await;
        pending.push_back((action.clone(), timestamp));

        // Execute action
        match action {
            AutomationAction::Log { level, message } => {
                match level.as_str() {
                    "info" => info!("Automation: {}", message),
                    "warn" => warn!("Automation: {}", message),
                    "error" => error!("Automation: {}", message),
                    _ => debug!("Automation: {}", message),
                }
            }
            AutomationAction::SendAlert { recipient, message } => {
                // In production, this would integrate with alerting systems
                info!("Alert to {}: {}", recipient, message);
            }
            _ => {
                debug!("Executing automation action: {:?}", action);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_event_emission() {
        let manager = EventManager::new(EventConfig::default());
        let connection_id = ConnectionId::new();

        let event = manager.create_connection_established_event(
            connection_id,
            "192.168.1.1:12345".to_string(),
            Some("http/1.1".to_string()),
            Some("example.com".to_string()),
        );

        manager.emit_event(event).await.unwrap();

        let stats = manager.get_stats().await;
        assert_eq!(stats.total_events_generated, 1);
    }

    #[tokio::test]
    async fn test_event_subscription() {
        let manager = EventManager::new(EventConfig::default());
        
        let mut rx = manager.subscribe(
            "test_subscriber".to_string(),
            vec![EventType::ConnectionEstablished],
            None,
        ).await.unwrap();

        let connection_id = ConnectionId::new();
        let event = manager.create_connection_established_event(
            connection_id,
            "192.168.1.1:12345".to_string(),
            None,
            None,
        );

        manager.emit_event(event).await.unwrap();

        let received_event = rx.recv().await.unwrap();
        assert_eq!(received_event.event_type, EventType::ConnectionEstablished);
    }

    #[tokio::test]
    async fn test_event_automation() {
        let manager = Arc::new(EventManager::new(EventConfig::default()));
        let automation = EventAutomation::new(manager.clone());

        let rule = AutomationRule {
            id: "test_rule".to_string(),
            name: "Test Rule".to_string(),
            enabled: true,
            trigger: EventTrigger::SingleEvent {
                event_type: EventType::SecurityViolation,
                condition: None,
            },
            actions: vec![AutomationAction::Log {
                level: "warn".to_string(),
                message: "Security event detected".to_string(),
            }],
            cooldown: Duration::from_secs(1),
            last_triggered: None,
        };

        automation.add_rule(rule).await;

        let event = manager.create_security_event(
            None,
            "ddos".to_string(),
            "high".to_string(),
            "Potential DDoS attack detected".to_string(),
        );

        automation.process_event(&event).await.unwrap();
    }
}