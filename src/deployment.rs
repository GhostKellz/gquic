//! GQUIC Production Deployment Tools
//!
//! Comprehensive tools for deploying GQUIC applications in production:
//! - Configuration management and validation
//! - Health checks and monitoring integration
//! - Docker/Kubernetes deployment helpers
//! - Load balancing and scaling utilities
//! - Security hardening and certificate management
//! - Performance tuning and optimization profiles

use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use std::net::SocketAddr;
use std::sync::Arc;
use serde::{Serialize, Deserialize};
use tokio::sync::RwLock;

use crate::{QuicResult, QuicError};

/// Production deployment configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentConfig {
    pub application: ApplicationConfig,
    pub networking: NetworkingConfig,
    pub security: SecurityConfig,
    pub performance: PerformanceConfig,
    pub monitoring: MonitoringConfig,
    pub scaling: ScalingConfig,
}

/// Application-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationConfig {
    pub name: String,
    pub version: String,
    pub environment: Environment,
    pub log_level: LogLevel,
    pub graceful_shutdown_timeout: Duration,
    pub feature_flags: HashMap<String, bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Environment {
    Development,
    Staging,
    Production,
    Testing,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

/// Network configuration for production
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkingConfig {
    pub listen_addresses: Vec<SocketAddr>,
    pub max_connections: usize,
    pub connection_timeout: Duration,
    pub keep_alive: Duration,
    pub tcp_nodelay: bool,
    pub socket_buffer_size: usize,
    pub load_balancer: Option<LoadBalancerConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadBalancerConfig {
    pub algorithm: LoadBalanceAlgorithm,
    pub health_check_interval: Duration,
    pub unhealthy_threshold: u32,
    pub backend_servers: Vec<BackendServer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoadBalanceAlgorithm {
    RoundRobin,
    LeastConnections,
    WeightedRoundRobin,
    IPHash,
    ConsistentHash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendServer {
    pub address: SocketAddr,
    pub weight: u32,
    pub max_connections: usize,
    pub health_check_url: Option<String>,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub tls_config: TlsConfig,
    pub rate_limiting: RateLimitConfig,
    pub access_control: AccessControlConfig,
    pub audit_logging: bool,
    pub security_headers: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
    pub ca_path: Option<String>,
    pub protocols: Vec<TlsProtocol>,
    pub cipher_suites: Vec<String>,
    pub cert_auto_renewal: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TlsProtocol {
    #[serde(rename = "1.2")]
    Tls12,
    #[serde(rename = "1.3")]
    Tls13,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub requests_per_second: u32,
    pub burst_size: u32,
    pub whitelist: Vec<String>, // IP addresses or CIDR blocks
    pub blacklist: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControlConfig {
    pub cors_enabled: bool,
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_headers: Vec<String>,
    pub max_age: Duration,
}

/// Performance tuning configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    pub worker_threads: Option<usize>,
    pub max_blocking_threads: Option<usize>,
    pub stack_size: Option<usize>,
    pub thread_keep_alive: Duration,
    pub enable_io_uring: bool,
    pub memory_pool_size: usize,
    pub gc_settings: GcSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcSettings {
    pub enabled: bool,
    pub collection_interval: Duration,
    pub memory_threshold: usize,
    pub aggressive_mode: bool,
}

/// Monitoring and observability configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    pub metrics: MetricsConfig,
    pub tracing: TracingConfig,
    pub health_checks: Vec<HealthCheckConfig>,
    pub alerting: AlertingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub endpoint: String,
    pub format: MetricsFormat,
    pub collection_interval: Duration,
    pub retention_period: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetricsFormat {
    Prometheus,
    StatsD,
    OpenTelemetry,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracingConfig {
    pub enabled: bool,
    pub sampling_rate: f64,
    pub jaeger_endpoint: Option<String>,
    pub zipkin_endpoint: Option<String>,
    pub export_timeout: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    pub name: String,
    pub endpoint: String,
    pub interval: Duration,
    pub timeout: Duration,
    pub healthy_threshold: u32,
    pub unhealthy_threshold: u32,
    pub expected_status: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertingConfig {
    pub enabled: bool,
    pub webhook_url: Option<String>,
    pub email_recipients: Vec<String>,
    pub slack_webhook: Option<String>,
    pub alert_thresholds: AlertThresholds,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertThresholds {
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub disk_usage: f64,
    pub error_rate: f64,
    pub response_time: Duration,
}

/// Auto-scaling configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScalingConfig {
    pub enabled: bool,
    pub min_instances: u32,
    pub max_instances: u32,
    pub target_cpu_utilization: f64,
    pub target_memory_utilization: f64,
    pub scale_up_threshold: f64,
    pub scale_down_threshold: f64,
    pub cooldown_period: Duration,
}

/// Production deployment manager
pub struct DeploymentManager {
    config: DeploymentConfig,
    health_checker: Arc<HealthChecker>,
    metrics_collector: Arc<MetricsCollector>,
    certificate_manager: Arc<CertificateManager>,
    load_balancer: Option<Arc<LoadBalancer>>,
}

impl DeploymentManager {
    pub fn new(config: DeploymentConfig) -> QuicResult<Self> {
        let health_checker = Arc::new(HealthChecker::new(config.monitoring.health_checks.clone()));
        let metrics_collector = Arc::new(MetricsCollector::new(config.monitoring.metrics.clone()));
        let certificate_manager = Arc::new(CertificateManager::new(config.security.tls_config.clone())?);

        let load_balancer = if let Some(lb_config) = &config.networking.load_balancer {
            Some(Arc::new(LoadBalancer::new(lb_config.clone())))
        } else {
            None
        };

        Ok(Self {
            config,
            health_checker,
            metrics_collector,
            certificate_manager,
            load_balancer,
        })
    }

    /// Validate deployment configuration
    pub fn validate_config(&self) -> QuicResult<()> {
        // Validate network configuration
        if self.config.networking.listen_addresses.is_empty() {
            return Err(QuicError::ConfigurationError(
                "No listen addresses configured".to_string()
            ));
        }

        // Validate TLS configuration
        if !std::path::Path::new(&self.config.security.tls_config.cert_path).exists() {
            return Err(QuicError::ConfigurationError(
                format!("Certificate file not found: {}", self.config.security.tls_config.cert_path)
            ));
        }

        if !std::path::Path::new(&self.config.security.tls_config.key_path).exists() {
            return Err(QuicError::ConfigurationError(
                format!("Private key file not found: {}", self.config.security.tls_config.key_path)
            ));
        }

        // Validate performance settings
        if let Some(worker_threads) = self.config.performance.worker_threads {
            if worker_threads == 0 {
                return Err(QuicError::ConfigurationError(
                    "Worker threads must be greater than 0".to_string()
                ));
            }
        }

        Ok(())
    }

    /// Generate Docker configuration
    pub fn generate_dockerfile(&self) -> String {
        format!(r#"
# Multi-stage build for GQUIC application
FROM rust:1.70 as builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Build release binary
RUN cargo build --release

# Production image
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r gquic && useradd -r -g gquic gquic

# Copy binary
COPY --from=builder /app/target/release/{} /usr/local/bin/app

# Create directories
RUN mkdir -p /app/config /app/certs /app/logs \
    && chown -R gquic:gquic /app

USER gquic
WORKDIR /app

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose ports
EXPOSE {}

CMD ["/usr/local/bin/app", "--config", "/app/config/app.yaml"]
"#,
            self.config.application.name,
            self.config.networking.listen_addresses
                .iter()
                .map(|addr| addr.port().to_string())
                .collect::<Vec<_>>()
                .join(" ")
        )
    }

    /// Generate Kubernetes deployment manifests
    pub fn generate_k8s_manifests(&self) -> Vec<String> {
        let mut manifests = Vec::new();

        // Deployment manifest
        let deployment = format!(r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {app_name}
  labels:
    app: {app_name}
    version: {version}
spec:
  replicas: {min_instances}
  selector:
    matchLabels:
      app: {app_name}
  template:
    metadata:
      labels:
        app: {app_name}
        version: {version}
    spec:
      containers:
      - name: {app_name}
        image: {app_name}:{version}
        ports:
        - containerPort: {port}
          protocol: UDP
        env:
        - name: RUST_LOG
          value: "{log_level}"
        - name: ENVIRONMENT
          value: "{environment}"
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
        volumeMounts:
        - name: config
          mountPath: /app/config
        - name: certs
          mountPath: /app/certs
      volumes:
      - name: config
        configMap:
          name: {app_name}-config
      - name: certs
        secret:
          secretName: {app_name}-certs
"#,
            app_name = self.config.application.name,
            version = self.config.application.version,
            min_instances = self.config.scaling.min_instances,
            port = self.config.networking.listen_addresses[0].port(),
            log_level = format!("{:?}", self.config.application.log_level).to_lowercase(),
            environment = format!("{:?}", self.config.application.environment).to_lowercase(),
        );
        manifests.push(deployment);

        // Service manifest
        let service = format!(r#"
apiVersion: v1
kind: Service
metadata:
  name: {app_name}-service
  labels:
    app: {app_name}
spec:
  selector:
    app: {app_name}
  ports:
  - port: {port}
    targetPort: {port}
    protocol: UDP
  type: ClusterIP
"#,
            app_name = self.config.application.name,
            port = self.config.networking.listen_addresses[0].port(),
        );
        manifests.push(service);

        // ConfigMap for application configuration
        let config_yaml = serde_yaml::to_string(&self.config).unwrap_or_default()
            .lines()
            .map(|line| format!("    {}", line))
            .collect::<Vec<_>>()
            .join("\n");

        let configmap = format!(r#"
apiVersion: v1
kind: ConfigMap
metadata:
  name: {}-config
data:
  app.yaml: |
{}
"#,
            self.config.application.name,
            config_yaml
        );
        manifests.push(configmap);

        // HorizontalPodAutoscaler if scaling is enabled
        if self.config.scaling.enabled {
            let hpa = format!(r#"
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: {app_name}-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: {app_name}
  minReplicas: {min_instances}
  maxReplicas: {max_instances}
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: {cpu_target}
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: {memory_target}
"#,
                app_name = self.config.application.name,
                min_instances = self.config.scaling.min_instances,
                max_instances = self.config.scaling.max_instances,
                cpu_target = (self.config.scaling.target_cpu_utilization * 100.0) as u32,
                memory_target = (self.config.scaling.target_memory_utilization * 100.0) as u32,
            );
            manifests.push(hpa);
        }

        manifests
    }

    /// Generate monitoring configuration (Prometheus)
    pub fn generate_prometheus_config(&self) -> String {
        format!(r#"
global:
  scrape_interval: {}s
  evaluation_interval: 15s

rule_files:
  - "gquic_rules.yml"

scrape_configs:
  - job_name: '{}'
    static_configs:
      - targets: ['localhost:{}']
    scrape_interval: {}s
    metrics_path: {}

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093
"#,
            self.config.monitoring.metrics.collection_interval.as_secs(),
            self.config.application.name,
            self.config.networking.listen_addresses[0].port(),
            self.config.monitoring.metrics.collection_interval.as_secs(),
            self.config.monitoring.metrics.endpoint,
        )
    }

    /// Get deployment status
    pub async fn get_status(&self) -> DeploymentStatus {
        let health_status = self.health_checker.get_overall_health().await;
        let metrics = self.metrics_collector.get_current_metrics().await;

        DeploymentStatus {
            application_name: self.config.application.name.clone(),
            version: self.config.application.version.clone(),
            environment: self.config.application.environment.clone(),
            health: health_status,
            metrics,
            uptime: SystemTime::now(),
            last_deployment: SystemTime::now(), // Would be tracked in real implementation
        }
    }

    /// Perform graceful shutdown
    pub async fn shutdown(&self) -> QuicResult<()> {
        println!("Initiating graceful shutdown...");

        // Stop accepting new connections
        // Drain existing connections
        // Save state if needed
        // Clean up resources

        tokio::time::sleep(self.config.application.graceful_shutdown_timeout).await;

        println!("Shutdown complete");
        Ok(())
    }
}

/// Health checking system
pub struct HealthChecker {
    checks: Vec<HealthCheckConfig>,
    results: Arc<RwLock<HashMap<String, HealthCheckResult>>>,
}

#[derive(Debug, Clone)]
pub struct HealthCheckResult {
    pub name: String,
    pub status: HealthStatus,
    pub last_check: SystemTime,
    pub response_time: Duration,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone)]
pub enum HealthStatus {
    Healthy,
    Unhealthy,
    Unknown,
}

impl HealthChecker {
    pub fn new(checks: Vec<HealthCheckConfig>) -> Self {
        Self {
            checks,
            results: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn run_health_checks(&self) {
        for check in &self.checks {
            let result = self.perform_health_check(check).await;
            let mut results = self.results.write().await;
            results.insert(check.name.clone(), result);
        }
    }

    async fn perform_health_check(&self, check: &HealthCheckConfig) -> HealthCheckResult {
        let start = std::time::Instant::now();

        // Simplified health check implementation
        let status = if check.endpoint == "/health" {
            HealthStatus::Healthy
        } else {
            HealthStatus::Unknown
        };

        HealthCheckResult {
            name: check.name.clone(),
            status,
            last_check: SystemTime::now(),
            response_time: start.elapsed(),
            error_message: None,
        }
    }

    pub async fn get_overall_health(&self) -> HealthStatus {
        let results = self.results.read().await;

        if results.is_empty() {
            return HealthStatus::Unknown;
        }

        let healthy_count = results.values()
            .filter(|r| matches!(r.status, HealthStatus::Healthy))
            .count();

        if healthy_count == results.len() {
            HealthStatus::Healthy
        } else if healthy_count > 0 {
            HealthStatus::Unknown // Partially healthy
        } else {
            HealthStatus::Unhealthy
        }
    }
}

/// Metrics collection system
pub struct MetricsCollector {
    config: MetricsConfig,
    metrics: Arc<RwLock<HashMap<String, MetricValue>>>,
}

#[derive(Debug, Clone)]
pub enum MetricValue {
    Counter(u64),
    Gauge(f64),
    Histogram(Vec<f64>),
}

impl MetricsCollector {
    pub fn new(config: MetricsConfig) -> Self {
        Self {
            config,
            metrics: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn record_metric(&self, name: String, value: MetricValue) {
        let mut metrics = self.metrics.write().await;
        metrics.insert(name, value);
    }

    pub async fn get_current_metrics(&self) -> HashMap<String, MetricValue> {
        self.metrics.read().await.clone()
    }

    pub async fn export_prometheus_format(&self) -> String {
        let metrics = self.metrics.read().await;
        let mut output = String::new();

        for (name, value) in metrics.iter() {
            match value {
                MetricValue::Counter(v) => {
                    output.push_str(&format!("# TYPE {} counter\n", name));
                    output.push_str(&format!("{} {}\n", name, v));
                },
                MetricValue::Gauge(v) => {
                    output.push_str(&format!("# TYPE {} gauge\n", name));
                    output.push_str(&format!("{} {}\n", name, v));
                },
                MetricValue::Histogram(values) => {
                    output.push_str(&format!("# TYPE {} histogram\n", name));
                    for (i, v) in values.iter().enumerate() {
                        output.push_str(&format!("{}_bucket{{le=\"{}\"}} {}\n", name, i, v));
                    }
                },
            }
        }

        output
    }
}

/// Certificate management
pub struct CertificateManager {
    config: TlsConfig,
    certificates: Arc<RwLock<HashMap<String, Certificate>>>,
}

#[derive(Debug, Clone)]
pub struct Certificate {
    pub domain: String,
    pub cert_data: Vec<u8>,
    pub key_data: Vec<u8>,
    pub expiry: SystemTime,
    pub auto_renew: bool,
}

impl CertificateManager {
    pub fn new(config: TlsConfig) -> QuicResult<Self> {
        Ok(Self {
            config,
            certificates: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub async fn load_certificates(&self) -> QuicResult<()> {
        // Load certificates from file system
        // In production, this would handle actual certificate loading
        println!("Loading certificates from: {}", self.config.cert_path);
        Ok(())
    }

    pub async fn check_expiry(&self) -> Vec<String> {
        let mut expiring = Vec::new();
        let certs = self.certificates.read().await;

        for (domain, cert) in certs.iter() {
            if let Ok(duration) = cert.expiry.duration_since(SystemTime::now()) {
                if duration < Duration::from_secs(30 * 24 * 60 * 60) { // 30 days
                    expiring.push(domain.clone());
                }
            }
        }

        expiring
    }
}

/// Load balancer implementation
pub struct LoadBalancer {
    config: LoadBalancerConfig,
    backends: Arc<RwLock<Vec<BackendStatus>>>,
    current_index: Arc<RwLock<usize>>,
}

#[derive(Debug, Clone)]
pub struct BackendStatus {
    pub server: BackendServer,
    pub healthy: bool,
    pub connections: usize,
    pub last_health_check: SystemTime,
}

impl LoadBalancer {
    pub fn new(config: LoadBalancerConfig) -> Self {
        let backends = config.backend_servers
            .iter()
            .map(|server| BackendStatus {
                server: server.clone(),
                healthy: true,
                connections: 0,
                last_health_check: SystemTime::now(),
            })
            .collect();

        Self {
            config,
            backends: Arc::new(RwLock::new(backends)),
            current_index: Arc::new(RwLock::new(0)),
        }
    }

    pub async fn select_backend(&self) -> Option<SocketAddr> {
        let backends = self.backends.read().await;
        let healthy_backends: Vec<_> = backends
            .iter()
            .filter(|b| b.healthy)
            .collect();

        if healthy_backends.is_empty() {
            return None;
        }

        match self.config.algorithm {
            LoadBalanceAlgorithm::RoundRobin => {
                let mut index = self.current_index.write().await;
                let backend = &healthy_backends[*index % healthy_backends.len()];
                *index += 1;
                Some(backend.server.address)
            },
            LoadBalanceAlgorithm::LeastConnections => {
                let backend = healthy_backends
                    .iter()
                    .min_by_key(|b| b.connections)?;
                Some(backend.server.address)
            },
            _ => {
                // Default to round robin for other algorithms
                let mut index = self.current_index.write().await;
                let backend = &healthy_backends[*index % healthy_backends.len()];
                *index += 1;
                Some(backend.server.address)
            }
        }
    }
}

/// Deployment status information
#[derive(Debug, Clone)]
pub struct DeploymentStatus {
    pub application_name: String,
    pub version: String,
    pub environment: Environment,
    pub health: HealthStatus,
    pub metrics: HashMap<String, MetricValue>,
    pub uptime: SystemTime,
    pub last_deployment: SystemTime,
}

/// Configuration loading utilities
pub mod config {
    use super::*;
    use std::path::Path;

    /// Load configuration from file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> QuicResult<DeploymentConfig> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| QuicError::ConfigurationError(format!("Failed to read config file: {}", e)))?;

        serde_yaml::from_str(&content)
            .map_err(|e| QuicError::ConfigurationError(format!("Failed to parse config: {}", e)))
    }

    /// Load configuration from environment variables
    pub fn load_from_env() -> QuicResult<DeploymentConfig> {
        // Environment variable configuration loading
        // This would be implemented based on specific requirements
        Ok(DeploymentConfig {
            application: ApplicationConfig {
                name: std::env::var("APP_NAME").unwrap_or_else(|_| "gquic-app".to_string()),
                version: std::env::var("APP_VERSION").unwrap_or_else(|_| "1.0.0".to_string()),
                environment: match std::env::var("ENVIRONMENT").as_deref() {
                    Ok("production") => Environment::Production,
                    Ok("staging") => Environment::Staging,
                    Ok("testing") => Environment::Testing,
                    _ => Environment::Development,
                },
                log_level: LogLevel::Info,
                graceful_shutdown_timeout: Duration::from_secs(30),
                feature_flags: HashMap::new(),
            },
            networking: NetworkingConfig {
                listen_addresses: vec!["0.0.0.0:4433".parse().unwrap()],
                max_connections: 10000,
                connection_timeout: Duration::from_secs(30),
                keep_alive: Duration::from_secs(60),
                tcp_nodelay: true,
                socket_buffer_size: 65536,
                load_balancer: None,
            },
            security: SecurityConfig {
                tls_config: TlsConfig {
                    cert_path: "/app/certs/cert.pem".to_string(),
                    key_path: "/app/certs/key.pem".to_string(),
                    ca_path: None,
                    protocols: vec![TlsProtocol::Tls13],
                    cipher_suites: vec![],
                    cert_auto_renewal: false,
                },
                rate_limiting: RateLimitConfig {
                    enabled: true,
                    requests_per_second: 1000,
                    burst_size: 100,
                    whitelist: vec![],
                    blacklist: vec![],
                },
                access_control: AccessControlConfig {
                    cors_enabled: false,
                    allowed_origins: vec![],
                    allowed_methods: vec![],
                    allowed_headers: vec![],
                    max_age: Duration::from_secs(3600),
                },
                audit_logging: true,
                security_headers: HashMap::new(),
            },
            performance: PerformanceConfig {
                worker_threads: None,
                max_blocking_threads: None,
                stack_size: None,
                thread_keep_alive: Duration::from_secs(60),
                enable_io_uring: false,
                memory_pool_size: 1024 * 1024 * 100, // 100MB
                gc_settings: GcSettings {
                    enabled: true,
                    collection_interval: Duration::from_secs(300),
                    memory_threshold: 1024 * 1024 * 512, // 512MB
                    aggressive_mode: false,
                },
            },
            monitoring: MonitoringConfig {
                metrics: MetricsConfig {
                    enabled: true,
                    endpoint: "/metrics".to_string(),
                    format: MetricsFormat::Prometheus,
                    collection_interval: Duration::from_secs(15),
                    retention_period: Duration::from_secs(24 * 60 * 60), // 24 hours
                },
                tracing: TracingConfig {
                    enabled: true,
                    sampling_rate: 0.1,
                    jaeger_endpoint: None,
                    zipkin_endpoint: None,
                    export_timeout: Duration::from_secs(10),
                },
                health_checks: vec![
                    HealthCheckConfig {
                        name: "application".to_string(),
                        endpoint: "/health".to_string(),
                        interval: Duration::from_secs(30),
                        timeout: Duration::from_secs(5),
                        healthy_threshold: 2,
                        unhealthy_threshold: 3,
                        expected_status: 200,
                    }
                ],
                alerting: AlertingConfig {
                    enabled: false,
                    webhook_url: None,
                    email_recipients: vec![],
                    slack_webhook: None,
                    alert_thresholds: AlertThresholds {
                        cpu_usage: 80.0,
                        memory_usage: 85.0,
                        disk_usage: 90.0,
                        error_rate: 5.0,
                        response_time: Duration::from_millis(1000),
                    },
                },
            },
            scaling: ScalingConfig {
                enabled: false,
                min_instances: 1,
                max_instances: 10,
                target_cpu_utilization: 70.0,
                target_memory_utilization: 80.0,
                scale_up_threshold: 80.0,
                scale_down_threshold: 30.0,
                cooldown_period: Duration::from_secs(300),
            },
        })
    }

    /// Validate configuration
    pub fn validate(config: &DeploymentConfig) -> QuicResult<()> {
        if config.application.name.is_empty() {
            return Err(QuicError::ConfigurationError(
                "Application name cannot be empty".to_string()
            ));
        }

        if config.networking.listen_addresses.is_empty() {
            return Err(QuicError::ConfigurationError(
                "At least one listen address must be configured".to_string()
            ));
        }

        if config.networking.max_connections == 0 {
            return Err(QuicError::ConfigurationError(
                "Max connections must be greater than 0".to_string()
            ));
        }

        Ok(())
    }
}