use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn, error};

use super::error::{QuicError, Result};

/// Application Layer Protocol Negotiation (ALPN) support for QUIC
/// Essential for crypto applications supporting multiple protocols (HTTP/3, custom protocols)
#[derive(Debug)]
pub struct AlpnManager {
    /// Supported protocols with their configurations
    supported_protocols: Arc<RwLock<HashMap<String, ProtocolConfig>>>,
    /// Protocol selection strategy
    selection_strategy: ProtocolSelectionStrategy,
    /// Default protocol if negotiation fails
    default_protocol: Option<String>,
    /// Protocol validation rules
    validation_rules: ProtocolValidationRules,
}

#[derive(Debug, Clone)]
pub struct ProtocolConfig {
    /// Protocol identifier (e.g., "h3", "custom-crypto-1.0")
    pub protocol_id: String,
    /// Human-readable description
    pub description: String,
    /// Protocol version
    pub version: String,
    /// Whether this protocol is enabled
    pub enabled: bool,
    /// Priority for protocol selection (higher = preferred)
    pub priority: u8,
    /// Supported features for this protocol
    pub features: ProtocolFeatures,
    /// Protocol-specific configuration
    pub config: ProtocolSpecificConfig,
}

#[derive(Debug, Clone)]
pub struct ProtocolFeatures {
    /// Supports server push
    pub supports_push: bool,
    /// Supports 0-RTT
    pub supports_0rtt: bool,
    /// Supports datagrams
    pub supports_datagrams: bool,
    /// Supports multiplexing
    pub supports_multiplexing: bool,
    /// Supports header compression
    pub supports_header_compression: bool,
    /// Custom feature flags
    pub custom_features: HashMap<String, bool>,
}

#[derive(Debug, Clone)]
pub enum ProtocolSpecificConfig {
    Http3 {
        max_field_section_size: Option<u64>,
        qpack_max_table_capacity: Option<u64>,
        qpack_blocked_streams: Option<u64>,
        enable_webtransport: bool,
    },
    Custom {
        protocol_data: HashMap<String, String>,
        binary_config: Option<Vec<u8>>,
        extensions: Vec<String>,
    },
    WebTransport {
        origins: Vec<String>,
        max_sessions: Option<u32>,
        session_timeout: Option<std::time::Duration>,
    },
}

#[derive(Debug, Clone)]
pub enum ProtocolSelectionStrategy {
    /// Prefer client's first supported protocol
    ClientPreference,
    /// Prefer server's highest priority protocol
    ServerPreference,
    /// Use custom selection logic
    Custom(String),
    /// Use protocol with best feature match
    FeatureBased,
}

#[derive(Debug, Clone)]
pub struct ProtocolValidationRules {
    /// Maximum protocol identifier length
    pub max_protocol_id_length: usize,
    /// Allowed characters in protocol IDs
    pub allowed_characters: HashSet<char>,
    /// Banned protocol prefixes
    pub banned_prefixes: Vec<String>,
    /// Required protocol features for crypto applications
    pub required_crypto_features: Vec<String>,
}

impl Default for ProtocolValidationRules {
    fn default() -> Self {
        let mut allowed_chars = HashSet::new();
        // RFC 7301: ALPN protocol names are sequences of non-empty bytes
        for c in 'a'..='z' {
            allowed_chars.insert(c);
        }
        for c in 'A'..='Z' {
            allowed_chars.insert(c);
        }
        for c in '0'..='9' {
            allowed_chars.insert(c);
        }
        allowed_chars.insert('-');
        allowed_chars.insert('_');
        allowed_chars.insert('.');
        allowed_chars.insert('/');

        Self {
            max_protocol_id_length: 255,
            allowed_characters: allowed_chars,
            banned_prefixes: vec![
                "test-".to_string(),
                "experimental-".to_string(),
            ],
            required_crypto_features: vec![
                "tls13".to_string(),
                "forward_secrecy".to_string(),
            ],
        }
    }
}

impl AlpnManager {
    pub fn new(selection_strategy: ProtocolSelectionStrategy) -> Self {
        Self {
            supported_protocols: Arc::new(RwLock::new(HashMap::new())),
            selection_strategy,
            default_protocol: None,
            validation_rules: ProtocolValidationRules::default(),
        }
    }

    /// Create ALPN manager with common crypto protocols
    pub fn new_crypto_optimized() -> Self {
        let mut manager = Self::new(ProtocolSelectionStrategy::ServerPreference);
        
        // Add HTTP/3 support
        let h3_config = ProtocolConfig {
            protocol_id: "h3".to_string(),
            description: "HTTP/3".to_string(),
            version: "1.0".to_string(),
            enabled: true,
            priority: 90,
            features: ProtocolFeatures {
                supports_push: true,
                supports_0rtt: true,
                supports_datagrams: true,
                supports_multiplexing: true,
                supports_header_compression: true,
                custom_features: HashMap::new(),
            },
            config: ProtocolSpecificConfig::Http3 {
                max_field_section_size: Some(16384),
                qpack_max_table_capacity: Some(4096),
                qpack_blocked_streams: Some(100),
                enable_webtransport: true,
            },
        };

        // Add custom crypto protocol
        let mut crypto_features = HashMap::new();
        crypto_features.insert("real_time_data".to_string(), true);
        crypto_features.insert("order_routing".to_string(), true);
        crypto_features.insert("market_data".to_string(), true);

        let crypto_config = ProtocolConfig {
            protocol_id: "crypto-quic/1.0".to_string(),
            description: "Custom Crypto Trading Protocol".to_string(),
            version: "1.0".to_string(),
            enabled: true,
            priority: 100, // Highest priority
            features: ProtocolFeatures {
                supports_push: false,
                supports_0rtt: true,
                supports_datagrams: true,
                supports_multiplexing: true,
                supports_header_compression: false,
                custom_features: crypto_features,
            },
            config: ProtocolSpecificConfig::Custom {
                protocol_data: {
                    let mut data = HashMap::new();
                    data.insert("trading_mode".to_string(), "high_frequency".to_string());
                    data.insert("market_data_format".to_string(), "binary".to_string());
                    data.insert("order_format".to_string(), "fix_binary".to_string());
                    data
                },
                binary_config: None,
                extensions: vec!["market_data".to_string(), "order_routing".to_string()],
            },
        };

        // Add WebTransport support
        let webtransport_config = ProtocolConfig {
            protocol_id: "wt".to_string(),
            description: "WebTransport".to_string(),
            version: "1.0".to_string(),
            enabled: true,
            priority: 80,
            features: ProtocolFeatures {
                supports_push: false,
                supports_0rtt: false,
                supports_datagrams: true,
                supports_multiplexing: true,
                supports_header_compression: false,
                custom_features: HashMap::new(),
            },
            config: ProtocolSpecificConfig::WebTransport {
                origins: vec!["*".to_string()], // Allow all origins for development
                max_sessions: Some(1000),
                session_timeout: Some(std::time::Duration::from_secs(300)),
            },
        };

        tokio::spawn({
            let protocols = manager.supported_protocols.clone();
            async move {
                let mut protocols = protocols.write().await;
                protocols.insert("h3".to_string(), h3_config);
                protocols.insert("crypto-quic/1.0".to_string(), crypto_config);
                protocols.insert("wt".to_string(), webtransport_config);
            }
        });

        manager.default_protocol = Some("h3".to_string());
        manager
    }

    /// Add a supported protocol
    pub async fn add_protocol(&self, config: ProtocolConfig) -> Result<()> {
        // Validate protocol configuration
        self.validate_protocol_config(&config)?;

        let mut protocols = self.supported_protocols.write().await;
        protocols.insert(config.protocol_id.clone(), config.clone());

        info!("Added ALPN protocol: {} ({})", config.protocol_id, config.description);
        Ok(())
    }

    /// Remove a protocol
    pub async fn remove_protocol(&self, protocol_id: &str) -> Result<bool> {
        let mut protocols = self.supported_protocols.write().await;
        let removed = protocols.remove(protocol_id).is_some();
        
        if removed {
            info!("Removed ALPN protocol: {}", protocol_id);
        }
        
        Ok(removed)
    }

    /// Enable or disable a protocol
    pub async fn set_protocol_enabled(&self, protocol_id: &str, enabled: bool) -> Result<()> {
        let mut protocols = self.supported_protocols.write().await;
        
        if let Some(config) = protocols.get_mut(protocol_id) {
            config.enabled = enabled;
            info!("Set protocol {} enabled: {}", protocol_id, enabled);
            Ok(())
        } else {
            Err(QuicError::Config(format!("Protocol not found: {}", protocol_id)))
        }
    }

    /// Get supported protocol identifiers for TLS ALPN extension
    pub async fn get_alpn_protocols(&self) -> Vec<String> {
        let protocols = self.supported_protocols.read().await;
        
        let mut enabled_protocols: Vec<_> = protocols.values()
            .filter(|config| config.enabled)
            .collect();

        // Sort by priority (highest first)
        enabled_protocols.sort_by(|a, b| b.priority.cmp(&a.priority));

        enabled_protocols.into_iter()
            .map(|config| config.protocol_id.clone())
            .collect()
    }

    /// Negotiate protocol from client's ALPN list
    pub async fn negotiate_protocol(&self, client_protocols: &[String]) -> Result<Option<NegotiationResult>> {
        let protocols = self.supported_protocols.read().await;
        
        let enabled_protocols: HashMap<_, _> = protocols.iter()
            .filter(|(_, config)| config.enabled)
            .collect();

        if enabled_protocols.is_empty() {
            return Ok(None);
        }

        let selected_protocol = match &self.selection_strategy {
            ProtocolSelectionStrategy::ClientPreference => {
                self.select_by_client_preference(client_protocols, &enabled_protocols)
            }
            ProtocolSelectionStrategy::ServerPreference => {
                self.select_by_server_preference(client_protocols, &enabled_protocols)
            }
            ProtocolSelectionStrategy::FeatureBased => {
                self.select_by_features(client_protocols, &enabled_protocols)
            }
            ProtocolSelectionStrategy::Custom(_) => {
                // For custom strategies, fall back to server preference
                self.select_by_server_preference(client_protocols, &enabled_protocols)
            }
        };

        if let Some((protocol_id, config)) = selected_protocol {
            debug!("Negotiated ALPN protocol: {}", protocol_id);
            
            Ok(Some(NegotiationResult {
                protocol_id: protocol_id.clone(),
                protocol_config: config.clone(),
                negotiated_features: self.extract_negotiated_features(&config),
            }))
        } else if let Some(ref default) = self.default_protocol {
            if let Some(config) = enabled_protocols.get(default) {
                warn!("Using default protocol: {}", default);
                
                Ok(Some(NegotiationResult {
                    protocol_id: default.clone(),
                    protocol_config: (*config).clone(),
                    negotiated_features: self.extract_negotiated_features(config),
                }))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    /// Select protocol by client preference
    fn select_by_client_preference(
        &self,
        client_protocols: &[String],
        enabled_protocols: &HashMap<&String, &ProtocolConfig>,
    ) -> Option<(String, ProtocolConfig)> {
        for client_protocol in client_protocols {
            if let Some(config) = enabled_protocols.get(client_protocol) {
                return Some((client_protocol.clone(), (*config).clone()));
            }
        }
        None
    }

    /// Select protocol by server preference (priority)
    fn select_by_server_preference(
        &self,
        client_protocols: &[String],
        enabled_protocols: &HashMap<&String, &ProtocolConfig>,
    ) -> Option<(String, ProtocolConfig)> {
        let client_set: HashSet<_> = client_protocols.iter().collect();
        
        let mut server_protocols: Vec<_> = enabled_protocols.iter()
            .filter(|(id, _)| client_set.contains(id))
            .collect();

        // Sort by server priority
        server_protocols.sort_by(|a, b| b.1.priority.cmp(&a.1.priority));

        server_protocols.first()
            .map(|(id, config)| ((*id).clone(), (*config).clone()))
    }

    /// Select protocol by feature matching
    fn select_by_features(
        &self,
        client_protocols: &[String],
        enabled_protocols: &HashMap<&String, &ProtocolConfig>,
    ) -> Option<(String, ProtocolConfig)> {
        let client_set: HashSet<_> = client_protocols.iter().collect();
        
        let mut scored_protocols: Vec<_> = enabled_protocols.iter()
            .filter(|(id, _)| client_set.contains(id))
            .map(|(id, config)| {
                let score = self.calculate_feature_score(config);
                (score, id, config)
            })
            .collect();

        // Sort by feature score (highest first)
        scored_protocols.sort_by(|a, b| b.0.cmp(&a.0));

        scored_protocols.first()
            .map(|(_, id, config)| ((*id).clone(), (*config).clone()))
    }

    /// Calculate feature score for protocol selection
    fn calculate_feature_score(&self, config: &ProtocolConfig) -> u32 {
        let mut score = config.priority as u32 * 10;

        let features = &config.features;
        if features.supports_0rtt { score += 20; }
        if features.supports_datagrams { score += 15; }
        if features.supports_multiplexing { score += 10; }
        if features.supports_header_compression { score += 5; }

        // Bonus for crypto-specific features
        for feature in &self.validation_rules.required_crypto_features {
            if features.custom_features.get(feature) == Some(&true) {
                score += 25;
            }
        }

        score
    }

    /// Extract negotiated features
    fn extract_negotiated_features(&self, config: &ProtocolConfig) -> HashMap<String, bool> {
        let mut features = HashMap::new();
        
        features.insert("supports_push".to_string(), config.features.supports_push);
        features.insert("supports_0rtt".to_string(), config.features.supports_0rtt);
        features.insert("supports_datagrams".to_string(), config.features.supports_datagrams);
        features.insert("supports_multiplexing".to_string(), config.features.supports_multiplexing);
        features.insert("supports_header_compression".to_string(), config.features.supports_header_compression);

        // Add custom features
        for (key, value) in &config.features.custom_features {
            features.insert(key.clone(), *value);
        }

        features
    }

    /// Validate protocol configuration
    fn validate_protocol_config(&self, config: &ProtocolConfig) -> Result<()> {
        // Check protocol ID length
        if config.protocol_id.len() > self.validation_rules.max_protocol_id_length {
            return Err(QuicError::Config(format!(
                "Protocol ID too long: {} > {}",
                config.protocol_id.len(),
                self.validation_rules.max_protocol_id_length
            )));
        }

        // Check allowed characters
        for c in config.protocol_id.chars() {
            if !self.validation_rules.allowed_characters.contains(&c) {
                return Err(QuicError::Config(format!(
                    "Invalid character in protocol ID: '{}'",
                    c
                )));
            }
        }

        // Check banned prefixes
        for banned_prefix in &self.validation_rules.banned_prefixes {
            if config.protocol_id.starts_with(banned_prefix) {
                return Err(QuicError::Config(format!(
                    "Protocol ID uses banned prefix: {}",
                    banned_prefix
                )));
            }
        }

        // Check for empty protocol ID
        if config.protocol_id.is_empty() {
            return Err(QuicError::Config("Protocol ID cannot be empty".to_string()));
        }

        Ok(())
    }

    /// Get protocol configuration
    pub async fn get_protocol_config(&self, protocol_id: &str) -> Option<ProtocolConfig> {
        let protocols = self.supported_protocols.read().await;
        protocols.get(protocol_id).cloned()
    }

    /// Get all supported protocols
    pub async fn get_all_protocols(&self) -> HashMap<String, ProtocolConfig> {
        self.supported_protocols.read().await.clone()
    }

    /// Set default protocol
    pub fn set_default_protocol(&mut self, protocol_id: Option<String>) {
        self.default_protocol = protocol_id;
    }

    /// Check if protocol is supported
    pub async fn is_protocol_supported(&self, protocol_id: &str) -> bool {
        let protocols = self.supported_protocols.read().await;
        protocols.get(protocol_id)
            .map(|config| config.enabled)
            .unwrap_or(false)
    }

    /// Get protocol statistics
    pub async fn get_protocol_stats(&self) -> ProtocolStats {
        let protocols = self.supported_protocols.read().await;
        
        let total_protocols = protocols.len();
        let enabled_protocols = protocols.values()
            .filter(|config| config.enabled)
            .count();

        let mut protocols_by_type = HashMap::new();
        for config in protocols.values() {
            let protocol_type = match &config.config {
                ProtocolSpecificConfig::Http3 { .. } => "HTTP/3",
                ProtocolSpecificConfig::Custom { .. } => "Custom",
                ProtocolSpecificConfig::WebTransport { .. } => "WebTransport",
            };
            *protocols_by_type.entry(protocol_type.to_string()).or_insert(0) += 1;
        }

        ProtocolStats {
            total_protocols,
            enabled_protocols,
            protocols_by_type,
            default_protocol: self.default_protocol.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NegotiationResult {
    pub protocol_id: String,
    pub protocol_config: ProtocolConfig,
    pub negotiated_features: HashMap<String, bool>,
}

#[derive(Debug, Clone)]
pub struct ProtocolStats {
    pub total_protocols: usize,
    pub enabled_protocols: usize,
    pub protocols_by_type: HashMap<String, usize>,
    pub default_protocol: Option<String>,
}

/// Helper functions for creating common protocol configurations
pub mod protocol_builders {
    use super::*;

    /// Create HTTP/3 protocol configuration
    pub fn http3() -> ProtocolConfig {
        ProtocolConfig {
            protocol_id: "h3".to_string(),
            description: "HTTP/3".to_string(),
            version: "1.0".to_string(),
            enabled: true,
            priority: 90,
            features: ProtocolFeatures {
                supports_push: true,
                supports_0rtt: true,
                supports_datagrams: true,
                supports_multiplexing: true,
                supports_header_compression: true,
                custom_features: HashMap::new(),
            },
            config: ProtocolSpecificConfig::Http3 {
                max_field_section_size: Some(16384),
                qpack_max_table_capacity: Some(4096),
                qpack_blocked_streams: Some(100),
                enable_webtransport: false,
            },
        }
    }

    /// Create WebTransport protocol configuration
    pub fn webtransport(origins: Vec<String>) -> ProtocolConfig {
        ProtocolConfig {
            protocol_id: "wt".to_string(),
            description: "WebTransport".to_string(),
            version: "1.0".to_string(),
            enabled: true,
            priority: 80,
            features: ProtocolFeatures {
                supports_push: false,
                supports_0rtt: false,
                supports_datagrams: true,
                supports_multiplexing: true,
                supports_header_compression: false,
                custom_features: HashMap::new(),
            },
            config: ProtocolSpecificConfig::WebTransport {
                origins,
                max_sessions: Some(1000),
                session_timeout: Some(std::time::Duration::from_secs(300)),
            },
        }
    }

    /// Create custom crypto protocol configuration
    pub fn crypto_protocol(
        protocol_id: String,
        trading_features: HashMap<String, bool>,
    ) -> ProtocolConfig {
        ProtocolConfig {
            protocol_id: protocol_id.clone(),
            description: format!("Custom Crypto Protocol: {}", protocol_id),
            version: "1.0".to_string(),
            enabled: true,
            priority: 100,
            features: ProtocolFeatures {
                supports_push: false,
                supports_0rtt: true,
                supports_datagrams: true,
                supports_multiplexing: true,
                supports_header_compression: false,
                custom_features: trading_features,
            },
            config: ProtocolSpecificConfig::Custom {
                protocol_data: HashMap::new(),
                binary_config: None,
                extensions: vec!["real_time".to_string(), "crypto".to_string()],
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_protocol_negotiation() {
        let manager = AlpnManager::new_crypto_optimized();
        
        // Test client prefers HTTP/3
        let client_protocols = vec!["h3".to_string(), "http/1.1".to_string()];
        let result = manager.negotiate_protocol(&client_protocols).await.unwrap();
        
        assert!(result.is_some());
        let negotiation = result.unwrap();
        // Should prefer our custom crypto protocol due to higher priority
        assert!(negotiation.protocol_id == "crypto-quic/1.0" || negotiation.protocol_id == "h3");
    }

    #[tokio::test]
    async fn test_protocol_management() {
        let manager = AlpnManager::new(ProtocolSelectionStrategy::ServerPreference);
        
        let config = protocol_builders::http3();
        manager.add_protocol(config).await.unwrap();
        
        assert!(manager.is_protocol_supported("h3").await);
        
        let protocols = manager.get_alpn_protocols().await;
        assert!(protocols.contains(&"h3".to_string()));
    }

    #[tokio::test]
    async fn test_crypto_protocol_features() {
        let mut features = HashMap::new();
        features.insert("high_frequency_trading".to_string(), true);
        features.insert("market_data_streaming".to_string(), true);
        
        let config = protocol_builders::crypto_protocol(
            "crypto-hft/1.0".to_string(),
            features,
        );
        
        assert_eq!(config.protocol_id, "crypto-hft/1.0");
        assert_eq!(config.priority, 100);
        assert!(config.features.supports_datagrams);
        assert!(config.features.supports_0rtt);
    }

    #[tokio::test]
    async fn test_protocol_validation() {
        let manager = AlpnManager::new(ProtocolSelectionStrategy::ClientPreference);
        
        // Test invalid protocol ID
        let invalid_config = ProtocolConfig {
            protocol_id: "invalid@protocol".to_string(), // @ is not allowed
            description: "Invalid".to_string(),
            version: "1.0".to_string(),
            enabled: true,
            priority: 50,
            features: ProtocolFeatures {
                supports_push: false,
                supports_0rtt: false,
                supports_datagrams: false,
                supports_multiplexing: false,
                supports_header_compression: false,
                custom_features: HashMap::new(),
            },
            config: ProtocolSpecificConfig::Custom {
                protocol_data: HashMap::new(),
                binary_config: None,
                extensions: Vec::new(),
            },
        };

        assert!(manager.add_protocol(invalid_config).await.is_err());
    }
}