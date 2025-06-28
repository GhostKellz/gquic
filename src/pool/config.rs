use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolConfig {
    /// Maximum number of connections per endpoint
    pub max_connections_per_endpoint: u32,
    
    /// Maximum age of a connection before it's considered stale
    pub max_connection_age: Duration,
    
    /// Maximum idle time before a connection is cleaned up
    pub max_idle_time: Duration,
    
    /// Interval for running connection cleanup
    pub cleanup_interval: Duration,
    
    /// Enable connection multiplexing
    pub enable_multiplexing: bool,
    
    /// Maximum number of concurrent streams per connection
    pub max_concurrent_streams: u32,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections_per_endpoint: 10,
            max_connection_age: Duration::from_secs(3600), // 1 hour
            max_idle_time: Duration::from_secs(300),       // 5 minutes
            cleanup_interval: Duration::from_secs(60),     // 1 minute
            enable_multiplexing: true,
            max_concurrent_streams: 100,
        }
    }
}

impl PoolConfig {
    pub fn builder() -> PoolConfigBuilder {
        PoolConfigBuilder::new()
    }
}

pub struct PoolConfigBuilder {
    config: PoolConfig,
}

impl PoolConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: PoolConfig::default(),
        }
    }

    pub fn max_connections_per_endpoint(mut self, max: u32) -> Self {
        self.config.max_connections_per_endpoint = max;
        self
    }

    pub fn max_connection_age(mut self, age: Duration) -> Self {
        self.config.max_connection_age = age;
        self
    }

    pub fn max_idle_time(mut self, idle: Duration) -> Self {
        self.config.max_idle_time = idle;
        self
    }

    pub fn cleanup_interval(mut self, interval: Duration) -> Self {
        self.config.cleanup_interval = interval;
        self
    }

    pub fn enable_multiplexing(mut self, enable: bool) -> Self {
        self.config.enable_multiplexing = enable;
        self
    }

    pub fn max_concurrent_streams(mut self, max: u32) -> Self {
        self.config.max_concurrent_streams = max;
        self
    }

    pub fn build(self) -> PoolConfig {
        self.config
    }
}

impl Default for PoolConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}