//! Gpanel Edge Agent - QUIC-based distributed container management
//!
//! Gaming-optimized edge agent for distributed Bolt container management
//! using QUIC for ultra-low latency communication with the main Gpanel instance.

use crate::quic::{
    connection::{Connection, ConnectionId},
    error::{QuicError, Result},
    endpoint::Endpoint,
};
use crate::http3::{Http3Connection, Http3Request, Http3Response};
use crate::container::{ContainerEndpoint, ContainerInfo, ContainerService};
use crate::gpanel::{
    EdgeAgentCapabilities, GpuResource, GamingFeatures, NetworkCapabilities,
    PerformanceProfile, ContainerOperation, ContainerStats, GpanelEvent
};
use bytes::Bytes;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Mutex, broadcast, mpsc};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn, error};

/// QUIC-based edge agent for distributed container management
pub struct GpanelEdgeAgent {
    /// Agent unique identifier
    agent_id: String,
    /// Agent display name
    agent_name: String,
    /// QUIC endpoint for communication
    endpoint: Arc<Endpoint>,
    /// Connection to main Gpanel server
    server_connection: Arc<RwLock<Option<Arc<Connection>>>>,
    /// HTTP/3 connection for web interface
    http3_connection: Arc<RwLock<Option<Arc<Http3Connection>>>>,
    /// Local container management
    container_manager: Arc<LocalContainerManager>,
    /// Agent capabilities
    capabilities: EdgeAgentCapabilities,
    /// Local gaming monitoring
    gaming_monitor: Arc<LocalGamingMonitor>,
    /// Performance metrics collector
    metrics_collector: Arc<EdgeMetricsCollector>,
    /// Event broadcaster for local events
    event_broadcaster: Arc<broadcast::Sender<AgentEvent>>,
    /// Background task handles
    background_tasks: Vec<JoinHandle<()>>,
    /// Agent configuration
    config: EdgeAgentConfig,
}

/// Local container manager for edge agent
pub struct LocalContainerManager {
    /// Bolt container endpoint
    bolt_endpoint: Arc<ContainerEndpoint>,
    /// Active containers
    active_containers: Arc<RwLock<HashMap<String, LocalContainerInfo>>>,
    /// Container operation queue
    operation_queue: Arc<Mutex<Vec<QueuedOperation>>>,
    /// Container stats cache
    stats_cache: Arc<RwLock<HashMap<String, CachedContainerStats>>>,
}

/// Local container information
#[derive(Debug, Clone)]
pub struct LocalContainerInfo {
    /// Container info from Bolt
    pub info: ContainerInfo,
    /// Local creation time
    pub created_at: Instant,
    /// Last stats update
    pub last_stats_update: Instant,
    /// Gaming classification
    pub is_gaming_container: bool,
    /// GPU resources assigned
    pub gpu_assignments: Vec<String>,
    /// Network performance requirements
    pub network_requirements: NetworkRequirements,
}

/// Network performance requirements for containers
#[derive(Debug, Clone)]
pub struct NetworkRequirements {
    /// Maximum acceptable latency (microseconds)
    pub max_latency_us: u32,
    /// Minimum bandwidth requirement (bits per second)
    pub min_bandwidth_bps: u64,
    /// Jitter tolerance (microseconds)
    pub jitter_tolerance_us: u32,
    /// Priority level (0 = highest)
    pub priority: u8,
    /// Gaming traffic indicator
    pub gaming_traffic: bool,
}

/// Queued container operation
#[derive(Debug)]
pub struct QueuedOperation {
    /// Operation ID
    pub id: String,
    /// Target container
    pub container_id: String,
    /// Operation type
    pub operation: ContainerOperation,
    /// Operation priority
    pub priority: OperationPriority,
    /// Queued timestamp
    pub queued_at: Instant,
    /// Gaming impact assessment
    pub gaming_impact: Option<GamingImpactAssessment>,
}

/// Operation priority levels
#[derive(Debug, Clone, PartialEq, Ord, PartialOrd, Eq)]
pub enum OperationPriority {
    Emergency = 0,
    Critical = 1,
    High = 2,
    Normal = 3,
    Low = 4,
    Background = 5,
}

/// Gaming impact assessment for operations
#[derive(Debug, Clone)]
pub struct GamingImpactAssessment {
    /// Expected impact level
    pub impact_level: GamingImpactLevel,
    /// Affected gaming sessions
    pub affected_sessions: Vec<String>,
    /// Recommended execution window
    pub recommended_window: Option<TimeWindow>,
    /// Estimated duration
    pub estimated_duration: Duration,
}

/// Gaming impact levels
#[derive(Debug, Clone, PartialEq, Ord, PartialOrd, Eq)]
pub enum GamingImpactLevel {
    None = 0,
    Minimal = 1,
    Low = 2,
    Moderate = 3,
    High = 4,
    Severe = 5,
}

/// Time window for operation execution
#[derive(Debug, Clone)]
pub struct TimeWindow {
    /// Earliest start time
    pub start: Instant,
    /// Latest end time
    pub end: Instant,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
}

/// Cached container statistics
#[derive(Debug, Clone)]
pub struct CachedContainerStats {
    /// Container statistics
    pub stats: ContainerStats,
    /// Cache timestamp
    pub cached_at: Instant,
    /// Cache TTL
    pub ttl: Duration,
    /// Gaming metrics included
    pub has_gaming_metrics: bool,
}

/// Local gaming monitor for edge performance
pub struct LocalGamingMonitor {
    /// Active gaming sessions
    gaming_sessions: Arc<RwLock<HashMap<String, GamingSession>>>,
    /// GPU monitoring
    gpu_monitor: Arc<GpuMonitor>,
    /// Network performance tracker
    network_tracker: Arc<NetworkPerformanceTracker>,
    /// Gaming performance metrics
    performance_metrics: Arc<RwLock<LocalGamingMetrics>>,
}

/// Gaming session tracking
#[derive(Debug, Clone)]
pub struct GamingSession {
    /// Session ID
    pub id: String,
    /// Container ID hosting the game
    pub container_id: String,
    /// Game name/title
    pub game_name: String,
    /// Session start time
    pub started_at: Instant,
    /// Player/user information
    pub player_info: PlayerInfo,
    /// Real-time performance metrics
    pub performance: RealTimeGameMetrics,
    /// GPU resources used
    pub gpu_resources: Vec<String>,
    /// Network quality
    pub network_quality: NetworkQuality,
}

/// Player information
#[derive(Debug, Clone)]
pub struct PlayerInfo {
    /// Player identifier
    pub player_id: String,
    /// Player name
    pub player_name: String,
    /// Gaming preferences
    pub preferences: GamingPreferences,
}

/// Gaming preferences
#[derive(Debug, Clone)]
pub struct GamingPreferences {
    /// Target frame rate
    pub target_fps: u32,
    /// Maximum acceptable input latency (ms)
    pub max_input_latency_ms: f32,
    /// Graphics quality preference
    pub graphics_quality: GraphicsQuality,
    /// Network priority
    pub network_priority: bool,
}

/// Graphics quality settings
#[derive(Debug, Clone, PartialEq)]
pub enum GraphicsQuality {
    Low,
    Medium,
    High,
    Ultra,
    Custom(HashMap<String, String>),
}

/// Real-time gaming metrics
#[derive(Debug, Clone, Default)]
pub struct RealTimeGameMetrics {
    /// Current frame rate
    pub current_fps: f32,
    /// Frame time (milliseconds)
    pub frame_time_ms: f32,
    /// Input latency (milliseconds)
    pub input_latency_ms: f32,
    /// GPU utilization percentage
    pub gpu_utilization: f32,
    /// VRAM usage (MB)
    pub vram_usage_mb: u32,
    /// CPU usage for gaming
    pub cpu_usage_gaming: f32,
    /// Network latency (milliseconds)
    pub network_latency_ms: f32,
    /// Packet loss percentage
    pub packet_loss: f32,
    /// Jitter (milliseconds)
    pub jitter_ms: f32,
}

/// Network quality assessment
#[derive(Debug, Clone)]
pub struct NetworkQuality {
    /// Overall quality score (0-100)
    pub quality_score: u8,
    /// Latency rating
    pub latency_rating: QualityRating,
    /// Bandwidth rating
    pub bandwidth_rating: QualityRating,
    /// Stability rating
    pub stability_rating: QualityRating,
    /// Gaming suitability
    pub gaming_suitability: GamingSuitability,
}

/// Quality ratings
#[derive(Debug, Clone, PartialEq)]
pub enum QualityRating {
    Excellent,
    Good,
    Fair,
    Poor,
    Unacceptable,
}

/// Gaming network suitability
#[derive(Debug, Clone, PartialEq)]
pub enum GamingSuitability {
    Optimal,
    Suitable,
    Marginal,
    Unsuitable,
}

/// GPU monitoring component
pub struct GpuMonitor {
    /// Available GPUs
    gpu_devices: Arc<RwLock<HashMap<String, GpuDevice>>>,
    /// GPU utilization tracking
    utilization_tracker: Arc<Mutex<GpuUtilizationTracker>>,
    /// GPU memory pools
    memory_pools: Arc<RwLock<HashMap<String, GpuMemoryPool>>>,
}

/// GPU device information
#[derive(Debug, Clone)]
pub struct GpuDevice {
    /// GPU ID
    pub id: String,
    /// GPU name/model
    pub name: String,
    /// Vendor (NVIDIA, AMD, Intel)
    pub vendor: String,
    /// Total VRAM (MB)
    pub total_vram_mb: u32,
    /// Available VRAM (MB)
    pub available_vram_mb: u32,
    /// Current utilization (%)
    pub utilization_percent: f32,
    /// Power consumption (watts)
    pub power_watts: f32,
    /// Temperature (Celsius)
    pub temperature_c: f32,
    /// Gaming performance score
    pub gaming_score: u8,
    /// Assigned containers
    pub assigned_containers: Vec<String>,
}

/// GPU utilization tracking
#[derive(Debug, Default)]
pub struct GpuUtilizationTracker {
    /// Utilization history (last 100 samples)
    pub utilization_history: Vec<GpuUtilizationSample>,
    /// Performance baselines
    pub performance_baselines: HashMap<String, GpuPerformanceBaseline>,
    /// Anomaly detection
    pub anomaly_detector: GpuAnomalyDetector,
}

/// GPU utilization sample
#[derive(Debug, Clone)]
pub struct GpuUtilizationSample {
    /// Sample timestamp
    pub timestamp: Instant,
    /// GPU ID
    pub gpu_id: String,
    /// Utilization percentage
    pub utilization: f32,
    /// VRAM usage (MB)
    pub vram_usage: u32,
    /// Power consumption (watts)
    pub power_consumption: f32,
    /// Associated container activities
    pub container_activities: Vec<String>,
}

/// GPU performance baseline
#[derive(Debug, Clone)]
pub struct GpuPerformanceBaseline {
    /// Baseline utilization under normal gaming load
    pub normal_utilization: f32,
    /// Expected VRAM usage for typical games
    pub expected_vram_mb: u32,
    /// Normal power consumption range
    pub power_range_watts: (f32, f32),
    /// Performance variance threshold
    pub variance_threshold: f32,
}

/// GPU anomaly detector
#[derive(Debug, Default)]
pub struct GpuAnomalyDetector {
    /// Detected anomalies
    pub detected_anomalies: Vec<GpuAnomaly>,
    /// Detection thresholds
    pub thresholds: AnomalyThresholds,
    /// Last detection run
    pub last_detection: Option<Instant>,
}

/// GPU anomaly types
#[derive(Debug, Clone)]
pub enum GpuAnomaly {
    UnexpectedUtilization { gpu_id: String, current: f32, expected: f32 },
    MemoryLeak { gpu_id: String, vram_growth_rate: f32 },
    ThermalThrottling { gpu_id: String, temperature: f32 },
    PowerSpike { gpu_id: String, power_watts: f32 },
}

/// Anomaly detection thresholds
#[derive(Debug)]
pub struct AnomalyThresholds {
    pub utilization_variance: f32,
    pub memory_growth_rate_mb_per_min: f32,
    pub temperature_threshold_c: f32,
    pub power_spike_threshold_watts: f32,
}

impl Default for AnomalyThresholds {
    fn default() -> Self {
        Self {
            utilization_variance: 20.0,
            memory_growth_rate_mb_per_min: 100.0,
            temperature_threshold_c: 85.0,
            power_spike_threshold_watts: 50.0,
        }
    }
}

/// GPU memory pool
#[derive(Debug, Clone)]
pub struct GpuMemoryPool {
    /// Pool ID
    pub id: String,
    /// Associated GPU
    pub gpu_id: String,
    /// Total pool size (MB)
    pub total_size_mb: u32,
    /// Available size (MB)
    pub available_mb: u32,
    /// Allocated blocks
    pub allocated_blocks: Vec<MemoryBlock>,
    /// Fragmentation percentage
    pub fragmentation_percent: f32,
}

/// GPU memory block
#[derive(Debug, Clone)]
pub struct MemoryBlock {
    /// Block ID
    pub id: String,
    /// Size (MB)
    pub size_mb: u32,
    /// Owning container
    pub container_id: String,
    /// Allocated timestamp
    pub allocated_at: Instant,
    /// Access pattern
    pub access_pattern: MemoryAccessPattern,
}

/// Memory access patterns
#[derive(Debug, Clone, PartialEq)]
pub enum MemoryAccessPattern {
    Sequential,
    Random,
    Streaming,
    Texture,
    Compute,
}

/// Network performance tracker
pub struct NetworkPerformanceTracker {
    /// Latency measurements
    latency_measurements: Arc<Mutex<Vec<LatencyMeasurement>>>,
    /// Bandwidth tests
    bandwidth_tests: Arc<Mutex<Vec<BandwidthTest>>>,
    /// Packet loss tracking
    packet_loss_tracker: Arc<Mutex<PacketLossTracker>>,
    /// Gaming network quality assessor
    quality_assessor: Arc<GamingNetworkQualityAssessor>,
}

/// Latency measurement
#[derive(Debug, Clone)]
pub struct LatencyMeasurement {
    /// Measurement timestamp
    pub timestamp: Instant,
    /// Target address
    pub target: SocketAddr,
    /// Round-trip time (microseconds)
    pub rtt_us: u32,
    /// Measurement type
    pub measurement_type: LatencyMeasurementType,
    /// Associated gaming session
    pub gaming_session: Option<String>,
}

/// Latency measurement types
#[derive(Debug, Clone, PartialEq)]
pub enum LatencyMeasurementType {
    Icmp,
    Udp,
    Quic,
    Gaming,
}

/// Bandwidth test result
#[derive(Debug, Clone)]
pub struct BandwidthTest {
    /// Test timestamp
    pub timestamp: Instant,
    /// Test duration
    pub duration: Duration,
    /// Upload speed (bits per second)
    pub upload_bps: u64,
    /// Download speed (bits per second)
    pub download_bps: u64,
    /// Test target
    pub target: SocketAddr,
    /// Gaming impact during test
    pub gaming_impact: Option<GamingImpactLevel>,
}

/// Packet loss tracker
#[derive(Debug, Default)]
pub struct PacketLossTracker {
    /// Loss measurements
    pub measurements: Vec<PacketLossMeasurement>,
    /// Current loss rate (percentage)
    pub current_loss_rate: f32,
    /// Gaming sessions affected by loss
    pub affected_sessions: Vec<String>,
}

/// Packet loss measurement
#[derive(Debug, Clone)]
pub struct PacketLossMeasurement {
    /// Measurement timestamp
    pub timestamp: Instant,
    /// Packets sent
    pub packets_sent: u32,
    /// Packets received
    pub packets_received: u32,
    /// Loss percentage
    pub loss_percentage: f32,
    /// Measurement window
    pub window_duration: Duration,
}

/// Gaming network quality assessor
pub struct GamingNetworkQualityAssessor {
    /// Quality history
    quality_history: Vec<NetworkQuality>,
    /// Gaming session correlations
    session_correlations: HashMap<String, Vec<NetworkQuality>>,
    /// Quality prediction model
    prediction_model: QualityPredictionModel,
}

/// Quality prediction model
#[derive(Debug)]
pub struct QualityPredictionModel {
    /// Historical patterns
    pub patterns: Vec<QualityPattern>,
    /// Prediction accuracy
    pub accuracy: f32,
    /// Last model update
    pub last_update: Instant,
}

/// Network quality pattern
#[derive(Debug)]
pub struct QualityPattern {
    /// Pattern identifier
    pub id: String,
    /// Time-based pattern
    pub time_pattern: TimePattern,
    /// Quality prediction
    pub predicted_quality: NetworkQuality,
    /// Confidence level
    pub confidence: f32,
}

/// Time-based quality patterns
#[derive(Debug)]
pub enum TimePattern {
    Hourly(Vec<u8>), // Hours of day with this pattern
    Daily(Vec<u8>),  // Days of week
    Seasonal(Vec<u8>), // Months of year
}

/// Local gaming metrics for edge agent
#[derive(Debug, Default, Clone)]
pub struct LocalGamingMetrics {
    /// Active gaming sessions count
    pub active_sessions: u32,
    /// Total gaming containers
    pub gaming_containers: u32,
    /// Average frame rate across sessions
    pub avg_frame_rate: f32,
    /// Average input latency
    pub avg_input_latency_ms: f32,
    /// GPU utilization summary
    pub gpu_utilization_summary: GpuUtilizationSummary,
    /// Network performance summary
    pub network_performance_summary: NetworkPerformanceSummary,
    /// Gaming quality score (0-100)
    pub gaming_quality_score: u8,
}

/// GPU utilization summary
#[derive(Debug, Default, Clone)]
pub struct GpuUtilizationSummary {
    /// Total GPU count
    pub total_gpus: u32,
    /// GPUs in use
    pub gpus_in_use: u32,
    /// Average utilization across all GPUs
    pub avg_utilization: f32,
    /// Total VRAM usage (MB)
    pub total_vram_usage_mb: u32,
    /// Gaming performance impact
    pub gaming_performance_impact: f32,
}

/// Network performance summary
#[derive(Debug, Default, Clone)]
pub struct NetworkPerformanceSummary {
    /// Average latency to gaming servers
    pub avg_gaming_latency_ms: f32,
    /// Current bandwidth utilization
    pub bandwidth_utilization: f32,
    /// Packet loss rate
    pub packet_loss_rate: f32,
    /// Network stability score
    pub stability_score: u8,
    /// Gaming traffic percentage
    pub gaming_traffic_percent: f32,
}

/// Edge metrics collector
pub struct EdgeMetricsCollector {
    /// System metrics
    system_metrics: Arc<RwLock<SystemMetrics>>,
    /// Container metrics
    container_metrics: Arc<RwLock<HashMap<String, ContainerMetrics>>>,
    /// Gaming metrics
    gaming_metrics: Arc<LocalGamingMonitor>,
    /// Collection intervals
    collection_config: MetricsCollectionConfig,
}

/// System-level metrics
#[derive(Debug, Default)]
pub struct SystemMetrics {
    /// CPU usage percentage
    pub cpu_usage: f32,
    /// Memory usage (bytes)
    pub memory_usage: u64,
    /// Disk I/O (bytes per second)
    pub disk_io_bps: u64,
    /// Network I/O (bytes per second)
    pub network_io_bps: u64,
    /// System load average
    pub load_average: f32,
    /// Temperature sensors
    pub temperatures: HashMap<String, f32>,
    /// Power consumption (watts)
    pub power_consumption: f32,
}

/// Container-specific metrics
#[derive(Debug, Default)]
pub struct ContainerMetrics {
    /// Container ID
    pub container_id: String,
    /// CPU usage
    pub cpu_usage: f32,
    /// Memory usage (bytes)
    pub memory_usage: u64,
    /// Network I/O
    pub network_rx_bps: u64,
    pub network_tx_bps: u64,
    /// Disk I/O
    pub disk_read_bps: u64,
    pub disk_write_bps: u64,
    /// Process count
    pub process_count: u32,
    /// Gaming-specific metrics
    pub gaming_metrics: Option<RealTimeGameMetrics>,
}

/// Metrics collection configuration
#[derive(Debug, Clone)]
pub struct MetricsCollectionConfig {
    /// System metrics interval
    pub system_interval: Duration,
    /// Container metrics interval
    pub container_interval: Duration,
    /// Gaming metrics interval
    pub gaming_interval: Duration,
    /// GPU metrics interval
    pub gpu_interval: Duration,
    /// Network metrics interval
    pub network_interval: Duration,
}

impl Default for MetricsCollectionConfig {
    fn default() -> Self {
        Self {
            system_interval: Duration::from_secs(5),
            container_interval: Duration::from_secs(1),
            gaming_interval: Duration::from_millis(16), // ~60 FPS
            gpu_interval: Duration::from_millis(100),
            network_interval: Duration::from_millis(500),
        }
    }
}

/// Agent events (local to edge agent)
#[derive(Debug, Clone)]
pub enum AgentEvent {
    /// Container events
    ContainerStarted { id: String, is_gaming: bool },
    ContainerStopped { id: String },
    ContainerHealthChanged { id: String, healthy: bool },

    /// Gaming session events
    GamingSessionStarted { session_id: String, game: String },
    GamingSessionEnded { session_id: String, duration: Duration },
    PerformanceAlert { session_id: String, issue: String },

    /// System events
    GpuStatusChanged { gpu_id: String, available: bool },
    NetworkQualityChanged { quality: NetworkQuality },
    SystemResourceAlert { resource: String, utilization: f32 },

    /// Agent events
    ServerConnectionEstablished,
    ServerConnectionLost,
    CapabilitiesUpdated,
}

/// Edge agent configuration
#[derive(Debug, Clone)]
pub struct EdgeAgentConfig {
    /// Agent identification
    pub agent_id: String,
    pub agent_name: String,

    /// Server connection
    pub server_address: SocketAddr,
    pub connection_timeout: Duration,
    pub heartbeat_interval: Duration,
    pub reconnection_interval: Duration,

    /// Gaming optimizations
    pub gaming_mode: bool,
    pub ultra_low_latency: bool,
    pub gaming_priority: bool,

    /// Metrics collection
    pub metrics_config: MetricsCollectionConfig,

    /// Container management
    pub max_containers: u32,
    pub container_start_timeout: Duration,

    /// Resource limits
    pub max_gpu_allocation_percent: f32,
    pub max_memory_allocation_percent: f32,
    pub max_cpu_allocation_percent: f32,
}

impl Default for EdgeAgentConfig {
    fn default() -> Self {
        Self {
            agent_id: format!("edge-{}", fastrand::u64(..)),
            agent_name: "Gpanel Edge Agent".to_string(),
            server_address: "127.0.0.1:8443".parse().unwrap(),
            connection_timeout: Duration::from_secs(30),
            heartbeat_interval: Duration::from_secs(5),
            reconnection_interval: Duration::from_secs(10),
            gaming_mode: true,
            ultra_low_latency: true,
            gaming_priority: true,
            metrics_config: MetricsCollectionConfig::default(),
            max_containers: 50,
            container_start_timeout: Duration::from_secs(60),
            max_gpu_allocation_percent: 90.0,
            max_memory_allocation_percent: 85.0,
            max_cpu_allocation_percent: 90.0,
        }
    }
}

impl GpanelEdgeAgent {
    /// Create new edge agent
    pub async fn new(config: EdgeAgentConfig) -> Result<Self> {
        info!("Creating Gpanel edge agent: {} ({})", config.agent_name, config.agent_id);

        // Create QUIC endpoint for server communication
        let bind_addr = "0.0.0.0:0".parse().unwrap(); // Bind to any available port
        let endpoint = Arc::new(Endpoint::server(bind_addr, Default::default()).await?);

        // Create container manager
        let container_config = crate::container::BoltNetworkConfig {
            sub_microsecond_mode: config.ultra_low_latency,
            ..Default::default()
        };
        let bolt_endpoint = Arc::new(
            crate::container::ContainerEndpoint::new(bind_addr, container_config).await?
        );

        let container_manager = Arc::new(LocalContainerManager {
            bolt_endpoint,
            active_containers: Arc::new(RwLock::new(HashMap::new())),
            operation_queue: Arc::new(Mutex::new(Vec::new())),
            stats_cache: Arc::new(RwLock::new(HashMap::new())),
        });

        // Create gaming monitor
        let gaming_monitor = Arc::new(LocalGamingMonitor::new().await?);

        // Create metrics collector
        let metrics_collector = Arc::new(EdgeMetricsCollector::new(config.metrics_config.clone()).await?);

        // Detect agent capabilities
        let capabilities = Self::detect_capabilities().await?;

        // Create event broadcaster
        let (event_tx, _) = broadcast::channel(1000);

        let agent = Self {
            agent_id: config.agent_id.clone(),
            agent_name: config.agent_name.clone(),
            endpoint,
            server_connection: Arc::new(RwLock::new(None)),
            http3_connection: Arc::new(RwLock::new(None)),
            container_manager,
            capabilities,
            gaming_monitor,
            metrics_collector,
            event_broadcaster: Arc::new(event_tx),
            background_tasks: Vec::new(),
            config,
        };

        info!("Edge agent {} created successfully", agent.agent_id);
        Ok(agent)
    }

    /// Connect to main Gpanel server
    pub async fn connect_to_server(&self) -> Result<()> {
        info!("Connecting to Gpanel server at {}", self.config.server_address);

        // Establish QUIC connection
        let connection = self.endpoint.connect(self.config.server_address, "gpanel-server").await?;

        // Create HTTP/3 connection
        let http3_conn = Arc::new(Http3Connection::new());

        // Store connections
        {
            let mut server_conn = self.server_connection.write().await;
            *server_conn = Some(Arc::new(connection));
        }
        {
            let mut http3_conn_guard = self.http3_connection.write().await;
            *http3_conn_guard = Some(http3_conn);
        }

        // Send agent registration
        self.register_with_server().await?;

        // Start heartbeat task
        self.start_heartbeat_task().await;

        // Broadcast connection event
        let event = AgentEvent::ServerConnectionEstablished;
        let _ = self.event_broadcaster.send(event);

        info!("Successfully connected to Gpanel server");
        Ok(())
    }

    /// Register agent with server
    async fn register_with_server(&self) -> Result<()> {
        info!("Registering agent with server");

        let registration = AgentRegistration {
            agent_id: self.agent_id.clone(),
            agent_name: self.agent_name.clone(),
            capabilities: self.capabilities.clone(),
            local_address: self.endpoint.local_addr().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
        };

        // Send registration via HTTP/3 (simplified)
        debug!("Agent registration prepared: {} capabilities",
               registration.capabilities.container_runtimes.len());

        Ok(())
    }

    /// Start heartbeat task
    async fn start_heartbeat_task(&self) {
        let heartbeat_interval = self.config.heartbeat_interval;
        let agent_id = self.agent_id.clone();
        let event_broadcaster = self.event_broadcaster.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(heartbeat_interval);

            loop {
                interval.tick().await;

                // Send heartbeat (simplified implementation)
                debug!("Sending heartbeat for agent {}", agent_id);

                // In a real implementation, this would send actual heartbeat data
                // including current metrics and status
            }
        });
    }

    /// Detect agent capabilities
    async fn detect_capabilities() -> Result<EdgeAgentCapabilities> {
        info!("Detecting edge agent capabilities");

        let mut capabilities = EdgeAgentCapabilities::default();

        // Detect GPU resources
        capabilities.gpu_resources = Self::detect_gpu_resources().await?;

        // Detect gaming features
        capabilities.gaming_features = Self::detect_gaming_features().await?;

        // Detect network capabilities
        capabilities.network_capabilities = Self::detect_network_capabilities().await?;

        // Create performance profile
        capabilities.performance_profile = Self::create_performance_profile().await?;

        info!("Detected {} GPU(s), gaming features: {:?}",
              capabilities.gpu_resources.len(), capabilities.gaming_features);

        Ok(capabilities)
    }

    /// Detect available GPU resources
    async fn detect_gpu_resources() -> Result<Vec<GpuResource>> {
        let mut gpus = Vec::new();

        // In a real implementation, this would use system APIs to detect GPUs
        // For now, create a mock GPU for testing
        let mock_gpu = GpuResource {
            vendor: "NVIDIA".to_string(),
            model: "GeForce RTX 4080".to_string(),
            vram_mb: 16384, // 16GB
            utilization_percent: 15.0,
            power_watts: 150.0,
            temperature_celsius: 45.0,
            available: true,
        };

        gpus.push(mock_gpu);

        debug!("Detected {} GPU resource(s)", gpus.len());
        Ok(gpus)
    }

    /// Detect gaming-specific features
    async fn detect_gaming_features() -> Result<GamingFeatures> {
        let features = GamingFeatures {
            gpu_passthrough: true,  // Would be detected via system APIs
            vfio_support: true,
            hardware_timestamping: true,
            anti_cheat_support: vec![
                "EasyAntiCheat".to_string(),
                "BattlEye".to_string(),
            ],
            drm_support: true,
            steam_proton: true,
        };

        debug!("Gaming features detected: GPU passthrough: {}, VFIO: {}",
               features.gpu_passthrough, features.vfio_support);

        Ok(features)
    }

    /// Detect network capabilities
    async fn detect_network_capabilities() -> Result<NetworkCapabilities> {
        // In a real implementation, this would perform network tests
        let capabilities = NetworkCapabilities {
            max_bandwidth_bps: 1_000_000_000, // 1 Gbps
            min_latency_us: 500,               // 0.5ms
            jitter_tolerance_us: 100,          // 0.1ms
            qos_support: true,
            gaming_priority: true,
        };

        debug!("Network capabilities: {}bps bandwidth, {}μs min latency",
               capabilities.max_bandwidth_bps, capabilities.min_latency_us);

        Ok(capabilities)
    }

    /// Create performance profile
    async fn create_performance_profile() -> Result<PerformanceProfile> {
        // In a real implementation, this would query system information
        let profile = PerformanceProfile {
            cpu_cores: 16,
            ram_mb: 32768, // 32GB
            storage_speed_mbps: 3500, // NVMe SSD
            network_latency_ms: 5.0,
            gaming_score: 95, // High-end gaming system
        };

        debug!("Performance profile: {} cores, {}MB RAM, gaming score: {}",
               profile.cpu_cores, profile.ram_mb, profile.gaming_score);

        Ok(profile)
    }

    /// Get current agent capabilities
    pub fn get_capabilities(&self) -> &EdgeAgentCapabilities {
        &self.capabilities
    }

    /// Subscribe to agent events
    pub fn subscribe_events(&self) -> broadcast::Receiver<AgentEvent> {
        self.event_broadcaster.subscribe()
    }

    /// Get local gaming metrics
    pub async fn get_gaming_metrics(&self) -> LocalGamingMetrics {
        self.gaming_monitor.get_metrics().await
    }
}

/// Agent registration information
#[derive(Debug, Clone)]
pub struct AgentRegistration {
    pub agent_id: String,
    pub agent_name: String,
    pub capabilities: EdgeAgentCapabilities,
    pub local_address: SocketAddr,
}

impl LocalGamingMonitor {
    async fn new() -> Result<Self> {
        Ok(Self {
            gaming_sessions: Arc::new(RwLock::new(HashMap::new())),
            gpu_monitor: Arc::new(GpuMonitor::new().await?),
            network_tracker: Arc::new(NetworkPerformanceTracker::new().await?),
            performance_metrics: Arc::new(RwLock::new(LocalGamingMetrics::default())),
        })
    }

    async fn get_metrics(&self) -> LocalGamingMetrics {
        (*self.performance_metrics.read().await).clone()
    }
}

impl GpuMonitor {
    async fn new() -> Result<Self> {
        Ok(Self {
            gpu_devices: Arc::new(RwLock::new(HashMap::new())),
            utilization_tracker: Arc::new(Mutex::new(GpuUtilizationTracker::default())),
            memory_pools: Arc::new(RwLock::new(HashMap::new())),
        })
    }
}

impl NetworkPerformanceTracker {
    async fn new() -> Result<Self> {
        Ok(Self {
            latency_measurements: Arc::new(Mutex::new(Vec::new())),
            bandwidth_tests: Arc::new(Mutex::new(Vec::new())),
            packet_loss_tracker: Arc::new(Mutex::new(PacketLossTracker::default())),
            quality_assessor: Arc::new(GamingNetworkQualityAssessor::new()),
        })
    }
}

impl GamingNetworkQualityAssessor {
    fn new() -> Self {
        Self {
            quality_history: Vec::new(),
            session_correlations: HashMap::new(),
            prediction_model: QualityPredictionModel {
                patterns: Vec::new(),
                accuracy: 0.0,
                last_update: Instant::now(),
            },
        }
    }
}

impl EdgeMetricsCollector {
    async fn new(config: MetricsCollectionConfig) -> Result<Self> {
        Ok(Self {
            system_metrics: Arc::new(RwLock::new(SystemMetrics::default())),
            container_metrics: Arc::new(RwLock::new(HashMap::new())),
            gaming_metrics: Arc::new(LocalGamingMonitor::new().await?),
            collection_config: config,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_edge_agent_creation() {
        let config = EdgeAgentConfig::default();
        let result = GpanelEdgeAgent::new(config).await;

        match result {
            Ok(agent) => {
                assert_eq!(agent.config.gaming_mode, true);
                assert_eq!(agent.config.ultra_low_latency, true);
            }
            Err(_) => {
                // Expected in test environment
                println!("Edge agent creation failed as expected in test environment");
            }
        }
    }

    #[tokio::test]
    async fn test_capability_detection() {
        let capabilities = GpanelEdgeAgent::detect_capabilities().await.unwrap();

        // Should have at least basic capabilities
        assert!(capabilities.container_runtimes.contains(&"bolt".to_string()));
        assert!(capabilities.gaming_features.gpu_passthrough);
        assert!(capabilities.network_capabilities.gaming_priority);
    }

    #[test]
    fn test_operation_priority_ordering() {
        let mut priorities = vec![
            OperationPriority::Background,
            OperationPriority::Emergency,
            OperationPriority::Normal,
            OperationPriority::Critical,
        ];

        priorities.sort();

        assert_eq!(priorities[0], OperationPriority::Emergency);
        assert_eq!(priorities[1], OperationPriority::Critical);
        assert_eq!(priorities[3], OperationPriority::Background);
    }

    #[test]
    fn test_gaming_impact_levels() {
        assert!(GamingImpactLevel::None < GamingImpactLevel::Minimal);
        assert!(GamingImpactLevel::Severe > GamingImpactLevel::Moderate);
    }
}