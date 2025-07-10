use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use std::path::Path;
use serde::{Serialize, Deserialize};
use tracing::{debug, info, warn, error};

use crate::quic::error::{QuicError, Result};

/// Comprehensive configuration validation system
/// Ensures all GQUIC configurations are valid and secure for crypto applications
#[derive(Debug)]
pub struct ConfigValidator {
    validation_rules: Vec<ValidationRule>,
    severity_threshold: ValidationSeverity,
    crypto_security_requirements: CryptoSecurityRequirements,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ValidationSeverity {
    Info = 0,
    Warning = 1,
    Error = 2,
    Critical = 3,
}

#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub recommendations: Vec<String>,
    pub security_score: u8, // 0-100
}

#[derive(Debug, Clone)]
pub struct ValidationIssue {
    pub severity: ValidationSeverity,
    pub category: ValidationCategory,
    pub message: String,
    pub field_path: String,
    pub suggestion: Option<String>,
    pub security_impact: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationCategory {
    Network,
    Security,
    Performance,
    Compatibility,
    Resource,
    Protocol,
    Crypto,
    Privacy,
}

#[derive(Debug, Clone)]
struct ValidationRule {
    name: String,
    category: ValidationCategory,
    severity: ValidationSeverity,
    check: ValidationCheck,
    description: String,
}

#[derive(Debug, Clone)]
enum ValidationCheck {
    Range { min: f64, max: f64 },
    DurationRange { min: Duration, max: Duration },
    NonEmpty,
    ValidAddress,
    ValidPort,
    ValidPath,
    SecureAlgorithm { allowed: Vec<String> },
    MutuallyExclusive { fields: Vec<String> },
    Dependency { required_field: String },
    Custom(String), // For complex validation logic
}

#[derive(Debug, Clone)]
struct CryptoSecurityRequirements {
    min_key_length: usize,
    allowed_cipher_suites: HashSet<String>,
    allowed_signature_algorithms: HashSet<String>,
    require_perfect_forward_secrecy: bool,
    min_tls_version: String,
    forbidden_algorithms: HashSet<String>,
}

impl Default for CryptoSecurityRequirements {
    fn default() -> Self {
        let mut allowed_cipher_suites = HashSet::new();
        allowed_cipher_suites.insert("TLS_AES_256_GCM_SHA384".to_string());
        allowed_cipher_suites.insert("TLS_AES_128_GCM_SHA256".to_string());
        allowed_cipher_suites.insert("TLS_CHACHA20_POLY1305_SHA256".to_string());

        let mut allowed_signature_algorithms = HashSet::new();
        allowed_signature_algorithms.insert("rsa_pss_rsae_sha256".to_string());
        allowed_signature_algorithms.insert("rsa_pss_rsae_sha384".to_string());
        allowed_signature_algorithms.insert("rsa_pss_rsae_sha512".to_string());
        allowed_signature_algorithms.insert("ecdsa_secp256r1_sha256".to_string());
        allowed_signature_algorithms.insert("ecdsa_secp384r1_sha384".to_string());
        allowed_signature_algorithms.insert("ed25519".to_string());

        let mut forbidden_algorithms = HashSet::new();
        forbidden_algorithms.insert("md5".to_string());
        forbidden_algorithms.insert("sha1".to_string());
        forbidden_algorithms.insert("rc4".to_string());
        forbidden_algorithms.insert("des".to_string());
        forbidden_algorithms.insert("3des".to_string());

        Self {
            min_key_length: 2048,
            allowed_cipher_suites,
            allowed_signature_algorithms,
            require_perfect_forward_secrecy: true,
            min_tls_version: "1.3".to_string(),
            forbidden_algorithms,
        }
    }
}

/// Complete GQUIC configuration structure for validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GquicConfig {
    // Network configuration
    pub bind_address: Option<SocketAddr>,
    pub max_connections: Option<u32>,
    pub max_streams_per_connection: Option<u64>,
    pub max_data: Option<u64>,
    pub max_stream_data: Option<u64>,
    
    // Timing configuration
    pub idle_timeout: Option<Duration>,
    pub max_ack_delay: Option<Duration>,
    pub handshake_timeout: Option<Duration>,
    pub keep_alive_interval: Option<Duration>,
    
    // Security configuration
    pub certificate_path: Option<String>,
    pub private_key_path: Option<String>,
    pub cipher_suites: Option<Vec<String>>,
    pub signature_algorithms: Option<Vec<String>>,
    pub alpn_protocols: Option<Vec<String>>,
    pub verify_peer: Option<bool>,
    
    // Crypto configuration
    pub enable_0rtt: Option<bool>,
    pub max_0rtt_data: Option<u64>,
    pub key_rotation_interval: Option<Duration>,
    pub session_ticket_lifetime: Option<Duration>,
    
    // Performance configuration
    pub congestion_control_algorithm: Option<String>,
    pub initial_rtt: Option<Duration>,
    pub min_rtt: Option<Duration>,
    pub packet_threshold: Option<u32>,
    pub time_threshold: Option<f64>,
    
    // Privacy configuration
    pub enable_connection_migration: Option<bool>,
    pub connection_id_length: Option<usize>,
    pub connection_id_rotation_interval: Option<Duration>,
    pub enable_privacy_protection: Option<bool>,
    
    // Feature configuration
    pub enable_datagrams: Option<bool>,
    pub max_datagram_size: Option<usize>,
    pub enable_bandwidth_estimation: Option<bool>,
    pub enable_loss_detection: Option<bool>,
    
    // Resource limits
    pub max_memory_usage: Option<u64>,
    pub max_cpu_usage: Option<f32>,
    pub max_file_descriptors: Option<u32>,
    pub receive_buffer_size: Option<usize>,
    pub send_buffer_size: Option<usize>,
}

impl ConfigValidator {
    pub fn new() -> Self {
        let mut validator = Self {
            validation_rules: Vec::new(),
            severity_threshold: ValidationSeverity::Warning,
            crypto_security_requirements: CryptoSecurityRequirements::default(),
        };

        validator.initialize_rules();
        validator
    }

    /// Initialize all validation rules
    fn initialize_rules(&mut self) {
        // Network validation rules
        self.add_rule(ValidationRule {
            name: "max_connections_range".to_string(),
            category: ValidationCategory::Network,
            severity: ValidationSeverity::Error,
            check: ValidationCheck::Range { min: 1.0, max: 1000000.0 },
            description: "Maximum connections must be between 1 and 1,000,000".to_string(),
        });

        self.add_rule(ValidationRule {
            name: "bind_address_valid".to_string(),
            category: ValidationCategory::Network,
            severity: ValidationSeverity::Error,
            check: ValidationCheck::ValidAddress,
            description: "Bind address must be a valid IP address and port".to_string(),
        });

        // Security validation rules
        self.add_rule(ValidationRule {
            name: "certificate_path_exists".to_string(),
            category: ValidationCategory::Security,
            severity: ValidationSeverity::Critical,
            check: ValidationCheck::ValidPath,
            description: "Certificate file must exist and be readable".to_string(),
        });

        self.add_rule(ValidationRule {
            name: "private_key_path_exists".to_string(),
            category: ValidationCategory::Security,
            severity: ValidationSeverity::Critical,
            check: ValidationCheck::ValidPath,
            description: "Private key file must exist and be readable".to_string(),
        });

        self.add_rule(ValidationRule {
            name: "secure_cipher_suites".to_string(),
            category: ValidationCategory::Crypto,
            severity: ValidationSeverity::Critical,
            check: ValidationCheck::SecureAlgorithm { 
                allowed: self.crypto_security_requirements.allowed_cipher_suites.iter().cloned().collect() 
            },
            description: "Only secure cipher suites should be used".to_string(),
        });

        // Performance validation rules
        self.add_rule(ValidationRule {
            name: "idle_timeout_range".to_string(),
            category: ValidationCategory::Performance,
            severity: ValidationSeverity::Warning,
            check: ValidationCheck::DurationRange {
                min: Duration::from_secs(10),
                max: Duration::from_secs(3600),
            },
            description: "Idle timeout should be between 10 seconds and 1 hour".to_string(),
        });

        self.add_rule(ValidationRule {
            name: "max_ack_delay_range".to_string(),
            category: ValidationCategory::Protocol,
            severity: ValidationSeverity::Error,
            check: ValidationCheck::DurationRange {
                min: Duration::from_millis(1),
                max: Duration::from_millis(25),
            },
            description: "Max ACK delay must be between 1ms and 25ms per RFC 9000".to_string(),
        });

        // Privacy validation rules
        self.add_rule(ValidationRule {
            name: "connection_id_length_range".to_string(),
            category: ValidationCategory::Privacy,
            severity: ValidationSeverity::Error,
            check: ValidationCheck::Range { min: 4.0, max: 18.0 },
            description: "Connection ID length must be between 4 and 18 bytes per RFC 9000".to_string(),
        });

        // Resource validation rules
        self.add_rule(ValidationRule {
            name: "memory_usage_reasonable".to_string(),
            category: ValidationCategory::Resource,
            severity: ValidationSeverity::Warning,
            check: ValidationCheck::Range { min: 1.0, max: 8_000_000_000.0 }, // 8GB max
            description: "Memory usage limit should be reasonable (max 8GB)".to_string(),
        });

        self.add_rule(ValidationRule {
            name: "cpu_usage_percentage".to_string(),
            category: ValidationCategory::Resource,
            severity: ValidationSeverity::Warning,
            check: ValidationCheck::Range { min: 0.1, max: 100.0 },
            description: "CPU usage should be between 0.1% and 100%".to_string(),
        });
    }

    /// Add a validation rule
    pub fn add_rule(&mut self, rule: ValidationRule) {
        self.validation_rules.push(rule);
    }

    /// Validate complete GQUIC configuration
    pub fn validate_config(&self, config: &GquicConfig) -> ValidationResult {
        let mut issues = Vec::new();
        let mut recommendations = Vec::new();

        // Validate each configuration field
        self.validate_network_config(config, &mut issues, &mut recommendations);
        self.validate_security_config(config, &mut issues, &mut recommendations);
        self.validate_performance_config(config, &mut issues, &mut recommendations);
        self.validate_crypto_config(config, &mut issues, &mut recommendations);
        self.validate_privacy_config(config, &mut issues, &mut recommendations);
        self.validate_resource_config(config, &mut issues, &mut recommendations);

        // Cross-validation checks
        self.validate_config_consistency(config, &mut issues, &mut recommendations);

        // Calculate security score
        let security_score = self.calculate_security_score(config, &issues);

        // Determine overall validity
        let valid = !issues.iter().any(|issue| {
            matches!(issue.severity, ValidationSeverity::Error | ValidationSeverity::Critical)
        });

        ValidationResult {
            valid,
            issues,
            recommendations,
            security_score,
        }
    }

    /// Validate network configuration
    fn validate_network_config(
        &self,
        config: &GquicConfig,
        issues: &mut Vec<ValidationIssue>,
        recommendations: &mut Vec<String>,
    ) {
        // Validate bind address
        if let Some(bind_addr) = &config.bind_address {
            if bind_addr.port() == 0 {
                issues.push(ValidationIssue {
                    severity: ValidationSeverity::Warning,
                    category: ValidationCategory::Network,
                    message: "Bind port is 0, will use random port".to_string(),
                    field_path: "bind_address.port".to_string(),
                    suggestion: Some("Consider using a specific port for production".to_string()),
                    security_impact: None,
                });
            }

            if bind_addr.ip().is_unspecified() {
                recommendations.push("Consider binding to specific interface for security".to_string());
            }
        }

        // Validate connection limits
        if let Some(max_connections) = config.max_connections {
            if max_connections > 100000 {
                issues.push(ValidationIssue {
                    severity: ValidationSeverity::Warning,
                    category: ValidationCategory::Resource,
                    message: "Very high connection limit may impact performance".to_string(),
                    field_path: "max_connections".to_string(),
                    suggestion: Some("Consider if this many connections are actually needed".to_string()),
                    security_impact: Some("High connection limits can be exploited for DoS attacks".to_string()),
                });
            }
        }

        // Validate stream limits
        if let Some(max_streams) = config.max_streams_per_connection {
            if max_streams > 1000 {
                recommendations.push("High stream count per connection may impact memory usage".to_string());
            }
        }
    }

    /// Validate security configuration
    fn validate_security_config(
        &self,
        config: &GquicConfig,
        issues: &mut Vec<ValidationIssue>,
        _recommendations: &mut Vec<String>,
    ) {
        // Validate certificate and key paths
        if let Some(cert_path) = &config.certificate_path {
            if !Path::new(cert_path).exists() {
                issues.push(ValidationIssue {
                    severity: ValidationSeverity::Critical,
                    category: ValidationCategory::Security,
                    message: "Certificate file does not exist".to_string(),
                    field_path: "certificate_path".to_string(),
                    suggestion: Some("Ensure certificate file exists and is readable".to_string()),
                    security_impact: Some("Missing certificate will prevent TLS handshake".to_string()),
                });
            }
        }

        if let Some(key_path) = &config.private_key_path {
            if !Path::new(key_path).exists() {
                issues.push(ValidationIssue {
                    severity: ValidationSeverity::Critical,
                    category: ValidationCategory::Security,
                    message: "Private key file does not exist".to_string(),
                    field_path: "private_key_path".to_string(),
                    suggestion: Some("Ensure private key file exists and is readable".to_string()),
                    security_impact: Some("Missing private key will prevent TLS handshake".to_string()),
                });
            }
        }

        // Validate cipher suites
        if let Some(cipher_suites) = &config.cipher_suites {
            for cipher_suite in cipher_suites {
                if self.crypto_security_requirements.forbidden_algorithms.contains(cipher_suite) {
                    issues.push(ValidationIssue {
                        severity: ValidationSeverity::Critical,
                        category: ValidationCategory::Crypto,
                        message: format!("Forbidden cipher suite: {}", cipher_suite),
                        field_path: "cipher_suites".to_string(),
                        suggestion: Some("Use only secure, modern cipher suites".to_string()),
                        security_impact: Some("Weak cipher suites can be compromised".to_string()),
                    });
                } else if !self.crypto_security_requirements.allowed_cipher_suites.contains(cipher_suite) {
                    issues.push(ValidationIssue {
                        severity: ValidationSeverity::Warning,
                        category: ValidationCategory::Crypto,
                        message: format!("Non-recommended cipher suite: {}", cipher_suite),
                        field_path: "cipher_suites".to_string(),
                        suggestion: Some("Consider using recommended cipher suites".to_string()),
                        security_impact: Some("Non-standard cipher suites may have unknown vulnerabilities".to_string()),
                    });
                }
            }
        }

        // Validate peer verification
        if let Some(verify_peer) = config.verify_peer {
            if !verify_peer {
                issues.push(ValidationIssue {
                    severity: ValidationSeverity::Warning,
                    category: ValidationCategory::Security,
                    message: "Peer verification is disabled".to_string(),
                    field_path: "verify_peer".to_string(),
                    suggestion: Some("Enable peer verification for production use".to_string()),
                    security_impact: Some("Disabled peer verification allows man-in-the-middle attacks".to_string()),
                });
            }
        }
    }

    /// Validate performance configuration
    fn validate_performance_config(
        &self,
        config: &GquicConfig,
        issues: &mut Vec<ValidationIssue>,
        recommendations: &mut Vec<String>,
    ) {
        // Validate timeouts
        if let Some(idle_timeout) = config.idle_timeout {
            if idle_timeout < Duration::from_secs(10) {
                issues.push(ValidationIssue {
                    severity: ValidationSeverity::Warning,
                    category: ValidationCategory::Performance,
                    message: "Very short idle timeout may cause unnecessary disconnections".to_string(),
                    field_path: "idle_timeout".to_string(),
                    suggestion: Some("Consider using at least 10 seconds for idle timeout".to_string()),
                    security_impact: None,
                });
            } else if idle_timeout > Duration::from_secs(3600) {
                recommendations.push("Long idle timeouts may waste resources".to_string());
            }
        }

        // Validate congestion control
        if let Some(cc_algo) = &config.congestion_control_algorithm {
            let valid_algorithms = ["newreno", "cubic", "bbr", "vegas"];
            if !valid_algorithms.contains(&cc_algo.as_str()) {
                issues.push(ValidationIssue {
                    severity: ValidationSeverity::Error,
                    category: ValidationCategory::Performance,
                    message: format!("Unknown congestion control algorithm: {}", cc_algo),
                    field_path: "congestion_control_algorithm".to_string(),
                    suggestion: Some("Use one of: newreno, cubic, bbr, vegas".to_string()),
                    security_impact: None,
                });
            }
        }

        // Validate buffer sizes
        if let Some(recv_buf) = config.receive_buffer_size {
            if recv_buf < 64 * 1024 { // 64KB
                recommendations.push("Small receive buffer may limit throughput".to_string());
            } else if recv_buf > 16 * 1024 * 1024 { // 16MB
                recommendations.push("Large receive buffer may waste memory".to_string());
            }
        }
    }

    /// Validate crypto configuration
    fn validate_crypto_config(
        &self,
        config: &GquicConfig,
        issues: &mut Vec<ValidationIssue>,
        recommendations: &mut Vec<String>,
    ) {
        // Validate 0-RTT configuration
        if let Some(enable_0rtt) = config.enable_0rtt {
            if enable_0rtt {
                if let Some(max_0rtt_data) = config.max_0rtt_data {
                    if max_0rtt_data > 100 * 1024 { // 100KB
                        issues.push(ValidationIssue {
                            severity: ValidationSeverity::Warning,
                            category: ValidationCategory::Security,
                            message: "Large 0-RTT data limit increases replay attack risk".to_string(),
                            field_path: "max_0rtt_data".to_string(),
                            suggestion: Some("Keep 0-RTT data limit small (< 100KB)".to_string()),
                            security_impact: Some("Large 0-RTT data can be replayed by attackers".to_string()),
                        });
                    }
                } else {
                    recommendations.push("Set explicit 0-RTT data limit when enabling 0-RTT".to_string());
                }
            }
        }

        // Validate key rotation
        if let Some(rotation_interval) = config.key_rotation_interval {
            if rotation_interval > Duration::from_secs(24 * 3600) { // 24 hours
                recommendations.push("Long key rotation intervals reduce forward secrecy".to_string());
            } else if rotation_interval < Duration::from_secs(60) { // 1 minute
                issues.push(ValidationIssue {
                    severity: ValidationSeverity::Warning,
                    category: ValidationCategory::Performance,
                    message: "Very frequent key rotation may impact performance".to_string(),
                    field_path: "key_rotation_interval".to_string(),
                    suggestion: Some("Consider key rotation interval of at least 1 minute".to_string()),
                    security_impact: None,
                });
            }
        }

        // Validate session ticket lifetime
        if let Some(ticket_lifetime) = config.session_ticket_lifetime {
            if ticket_lifetime > Duration::from_secs(7 * 24 * 3600) { // 7 days
                issues.push(ValidationIssue {
                    severity: ValidationSeverity::Warning,
                    category: ValidationCategory::Security,
                    message: "Long session ticket lifetime reduces forward secrecy".to_string(),
                    field_path: "session_ticket_lifetime".to_string(),
                    suggestion: Some("Keep session ticket lifetime under 7 days".to_string()),
                    security_impact: Some("Long-lived tickets increase exposure window".to_string()),
                });
            }
        }
    }

    /// Validate privacy configuration
    fn validate_privacy_config(
        &self,
        config: &GquicConfig,
        issues: &mut Vec<ValidationIssue>,
        recommendations: &mut Vec<String>,
    ) {
        // Validate connection ID configuration
        if let Some(cid_length) = config.connection_id_length {
            if cid_length < 4 || cid_length > 18 {
                issues.push(ValidationIssue {
                    severity: ValidationSeverity::Error,
                    category: ValidationCategory::Protocol,
                    message: "Connection ID length must be between 4 and 18 bytes".to_string(),
                    field_path: "connection_id_length".to_string(),
                    suggestion: Some("Use connection ID length between 4 and 18 bytes".to_string()),
                    security_impact: None,
                });
            } else if cid_length < 8 {
                recommendations.push("Short connection IDs provide less privacy protection".to_string());
            }
        }

        // Validate connection migration
        if let Some(enable_migration) = config.enable_connection_migration {
            if enable_migration && config.enable_privacy_protection != Some(true) {
                recommendations.push("Enable privacy protection when using connection migration".to_string());
            }
        }

        // Validate connection ID rotation
        if let Some(rotation_interval) = config.connection_id_rotation_interval {
            if rotation_interval > Duration::from_secs(3600) { // 1 hour
                recommendations.push("Long connection ID rotation intervals reduce privacy".to_string());
            } else if rotation_interval < Duration::from_secs(60) { // 1 minute
                issues.push(ValidationIssue {
                    severity: ValidationSeverity::Warning,
                    category: ValidationCategory::Performance,
                    message: "Very frequent connection ID rotation may impact performance".to_string(),
                    field_path: "connection_id_rotation_interval".to_string(),
                    suggestion: Some("Consider rotation interval of at least 1 minute".to_string()),
                    security_impact: None,
                });
            }
        }
    }

    /// Validate resource configuration
    fn validate_resource_config(
        &self,
        config: &GquicConfig,
        issues: &mut Vec<ValidationIssue>,
        recommendations: &mut Vec<String>,
    ) {
        // Validate memory usage
        if let Some(max_memory) = config.max_memory_usage {
            let gb = max_memory as f64 / (1024.0 * 1024.0 * 1024.0);
            if gb > 16.0 {
                issues.push(ValidationIssue {
                    severity: ValidationSeverity::Warning,
                    category: ValidationCategory::Resource,
                    message: format!("Very high memory limit: {:.1}GB", gb),
                    field_path: "max_memory_usage".to_string(),
                    suggestion: Some("Consider if this much memory is actually needed".to_string()),
                    security_impact: Some("High memory usage can lead to resource exhaustion".to_string()),
                });
            }
        }

        // Validate CPU usage
        if let Some(max_cpu) = config.max_cpu_usage {
            if max_cpu > 100.0 {
                issues.push(ValidationIssue {
                    severity: ValidationSeverity::Error,
                    category: ValidationCategory::Resource,
                    message: "CPU usage cannot exceed 100%".to_string(),
                    field_path: "max_cpu_usage".to_string(),
                    suggestion: Some("Set CPU usage limit to 100% or less".to_string()),
                    security_impact: None,
                });
            } else if max_cpu > 80.0 {
                recommendations.push("High CPU limits may impact system responsiveness".to_string());
            }
        }

        // Validate file descriptor limits
        if let Some(max_fds) = config.max_file_descriptors {
            if max_fds > 65536 {
                recommendations.push("Very high file descriptor limit may not be supported on all systems".to_string());
            } else if max_fds < 1024 {
                issues.push(ValidationIssue {
                    severity: ValidationSeverity::Warning,
                    category: ValidationCategory::Resource,
                    message: "Low file descriptor limit may cause connection failures".to_string(),
                    field_path: "max_file_descriptors".to_string(),
                    suggestion: Some("Consider increasing file descriptor limit".to_string()),
                    security_impact: None,
                });
            }
        }
    }

    /// Validate configuration consistency
    fn validate_config_consistency(
        &self,
        config: &GquicConfig,
        issues: &mut Vec<ValidationIssue>,
        recommendations: &mut Vec<String>,
    ) {
        // Check 0-RTT and security
        if config.enable_0rtt == Some(true) && config.verify_peer == Some(false) {
            issues.push(ValidationIssue {
                severity: ValidationSeverity::Critical,
                category: ValidationCategory::Security,
                message: "0-RTT with disabled peer verification is extremely insecure".to_string(),
                field_path: "enable_0rtt,verify_peer".to_string(),
                suggestion: Some("Either disable 0-RTT or enable peer verification".to_string()),
                security_impact: Some("Allows trivial replay attacks and impersonation".to_string()),
            });
        }

        // Check datagram and size limits
        if config.enable_datagrams == Some(true) {
            if let Some(datagram_size) = config.max_datagram_size {
                if datagram_size > 1500 {
                    recommendations.push("Large datagram size may cause fragmentation".to_string());
                }
            }
        }

        // Check migration and privacy
        if config.enable_connection_migration == Some(true) {
            if config.connection_id_rotation_interval.is_none() {
                recommendations.push("Enable connection ID rotation when using migration for better privacy".to_string());
            }
        }

        // Check resource consistency
        if let (Some(max_mem), Some(max_conn)) = (config.max_memory_usage, config.max_connections) {
            let mem_per_conn = max_mem / max_conn as u64;
            if mem_per_conn < 1024 * 1024 { // 1MB per connection
                issues.push(ValidationIssue {
                    severity: ValidationSeverity::Warning,
                    category: ValidationCategory::Resource,
                    message: "Very low memory per connection may cause failures".to_string(),
                    field_path: "max_memory_usage,max_connections".to_string(),
                    suggestion: Some("Increase memory limit or reduce connection limit".to_string()),
                    security_impact: None,
                });
            }
        }
    }

    /// Calculate security score based on configuration
    fn calculate_security_score(&self, config: &GquicConfig, issues: &[ValidationIssue]) -> u8 {
        let mut score = 100u8;

        // Deduct points for security issues
        for issue in issues {
            match issue.severity {
                ValidationSeverity::Critical => score = score.saturating_sub(25),
                ValidationSeverity::Error => score = score.saturating_sub(10),
                ValidationSeverity::Warning => score = score.saturating_sub(5),
                ValidationSeverity::Info => score = score.saturating_sub(1),
            }
        }

        // Bonus points for good security practices
        if config.verify_peer == Some(true) {
            score = score.saturating_add(5).min(100);
        }

        if config.enable_privacy_protection == Some(true) {
            score = score.saturating_add(5).min(100);
        }

        if config.connection_id_rotation_interval.is_some() {
            score = score.saturating_add(3).min(100);
        }

        score
    }

    /// Generate security recommendations for crypto applications
    pub fn generate_crypto_security_recommendations(&self, config: &GquicConfig) -> Vec<String> {
        let mut recommendations = Vec::new();

        recommendations.push("Use TLS 1.3 only for maximum security".to_string());
        recommendations.push("Enable perfect forward secrecy".to_string());
        recommendations.push("Implement proper key rotation".to_string());
        recommendations.push("Use strong cipher suites (AES-256-GCM, ChaCha20-Poly1305)".to_string());
        recommendations.push("Enable connection ID rotation for privacy".to_string());
        recommendations.push("Implement proper certificate validation".to_string());
        recommendations.push("Use secure random number generation".to_string());
        recommendations.push("Monitor for certificate expiration".to_string());
        recommendations.push("Implement proper session management".to_string());
        recommendations.push("Use HSTS and certificate pinning where possible".to_string());

        // Specific recommendations based on config
        if config.enable_0rtt == Some(true) {
            recommendations.push("Implement anti-replay protection for 0-RTT data".to_string());
            recommendations.push("Limit 0-RTT data to idempotent operations only".to_string());
        }

        if config.enable_datagrams == Some(true) {
            recommendations.push("Validate all datagram payloads".to_string());
            recommendations.push("Implement rate limiting for datagrams".to_string());
        }

        recommendations
    }
}

impl Default for ConfigValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_validation_success() {
        let validator = ConfigValidator::new();
        
        let config = GquicConfig {
            bind_address: Some("127.0.0.1:8443".parse().unwrap()),
            max_connections: Some(1000),
            max_streams_per_connection: Some(100),
            idle_timeout: Some(Duration::from_secs(300)),
            verify_peer: Some(true),
            enable_privacy_protection: Some(true),
            connection_id_length: Some(8),
            ..Default::default()
        };

        let result = validator.validate_config(&config);
        assert!(result.valid);
        assert!(result.security_score > 80);
    }

    #[test]
    fn test_config_validation_security_issues() {
        let validator = ConfigValidator::new();
        
        let config = GquicConfig {
            verify_peer: Some(false),
            enable_0rtt: Some(true),
            max_0rtt_data: Some(1024 * 1024), // 1MB - too large
            cipher_suites: Some(vec!["md5".to_string()]), // Forbidden
            connection_id_length: Some(2), // Too short
            ..Default::default()
        };

        let result = validator.validate_config(&config);
        assert!(!result.valid);
        assert!(result.security_score < 50);
        
        let critical_issues: Vec<_> = result.issues.iter()
            .filter(|issue| issue.severity == ValidationSeverity::Critical)
            .collect();
        assert!(!critical_issues.is_empty());
    }

    #[test]
    fn test_crypto_security_recommendations() {
        let validator = ConfigValidator::new();
        let config = GquicConfig::default();
        
        let recommendations = validator.generate_crypto_security_recommendations(&config);
        assert!(!recommendations.is_empty());
        assert!(recommendations.iter().any(|r| r.contains("TLS 1.3")));
        assert!(recommendations.iter().any(|r| r.contains("forward secrecy")));
    }
}

impl Default for GquicConfig {
    fn default() -> Self {
        Self {
            bind_address: None,
            max_connections: Some(10000),
            max_streams_per_connection: Some(100),
            max_data: Some(10 * 1024 * 1024), // 10MB
            max_stream_data: Some(1024 * 1024), // 1MB
            idle_timeout: Some(Duration::from_secs(300)),
            max_ack_delay: Some(Duration::from_millis(25)),
            handshake_timeout: Some(Duration::from_secs(10)),
            keep_alive_interval: Some(Duration::from_secs(30)),
            certificate_path: None,
            private_key_path: None,
            cipher_suites: None,
            signature_algorithms: None,
            alpn_protocols: Some(vec!["h3".to_string()]),
            verify_peer: Some(true),
            enable_0rtt: Some(false),
            max_0rtt_data: Some(16384), // 16KB
            key_rotation_interval: Some(Duration::from_secs(3600)),
            session_ticket_lifetime: Some(Duration::from_secs(24 * 3600)),
            congestion_control_algorithm: Some("cubic".to_string()),
            initial_rtt: Some(Duration::from_millis(100)),
            min_rtt: Some(Duration::from_millis(1)),
            packet_threshold: Some(3),
            time_threshold: Some(9.0 / 8.0),
            enable_connection_migration: Some(true),
            connection_id_length: Some(8),
            connection_id_rotation_interval: Some(Duration::from_secs(300)),
            enable_privacy_protection: Some(true),
            enable_datagrams: Some(true),
            max_datagram_size: Some(1200),
            enable_bandwidth_estimation: Some(true),
            enable_loss_detection: Some(true),
            max_memory_usage: Some(1024 * 1024 * 1024), // 1GB
            max_cpu_usage: Some(80.0),
            max_file_descriptors: Some(10000),
            receive_buffer_size: Some(2 * 1024 * 1024), // 2MB
            send_buffer_size: Some(2 * 1024 * 1024), // 2MB
        }
    }
}