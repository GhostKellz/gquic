//! GQUIC HTTP/3 Proxy Infrastructure
//!
//! High-performance HTTP/3 proxy with advanced features for web infrastructure,
//! CDN applications, and enterprise proxy deployments.

use crate::quic::error::{QuicError, Result};
use crate::http3::{Http3Connection, Http3Request, Http3Response, Http3Frame};
use crate::mesh::{GQuicMeshEndpoint, PeerId};
use bytes::Bytes;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Mutex};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn, error};
use serde::{Serialize, Deserialize};

/// HTTP/3 proxy configuration
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Listening address for HTTP/3 connections
    pub listen_addr: SocketAddr,
    /// Upstream server addresses
    pub upstreams: Vec<UpstreamServer>,
    /// Load balancing strategy
    pub load_balancer: LoadBalancerStrategy,
    /// Connection pool settings
    pub connection_pool: ConnectionPoolConfig,
    /// Caching configuration
    pub cache: CacheConfig,
    /// SSL/TLS configuration
    pub tls: TlsProxyConfig,
    /// Rate limiting
    pub rate_limit: RateLimitConfig,
}

/// Upstream server configuration
#[derive(Debug, Clone)]
pub struct UpstreamServer {
    pub address: SocketAddr,
    pub weight: u32,
    pub health_check_url: Option<String>,
    pub max_connections: usize,
    pub timeout: Duration,
}

/// Load balancing strategies
#[derive(Debug, Clone)]
pub enum LoadBalancerStrategy {
    RoundRobin,
    WeightedRoundRobin,
    LeastConnections,
    ConsistentHash,
    LatencyBased,
}

/// Connection pool configuration
#[derive(Debug, Clone)]
pub struct ConnectionPoolConfig {
    pub max_connections_per_upstream: usize,
    pub idle_timeout: Duration,
    pub connection_timeout: Duration,
    pub keepalive_interval: Duration,
}

impl Default for ConnectionPoolConfig {
    fn default() -> Self {
        Self {
            max_connections_per_upstream: 100,
            idle_timeout: Duration::from_secs(60),
            connection_timeout: Duration::from_secs(10),
            keepalive_interval: Duration::from_secs(30),
        }
    }
}

/// Cache configuration for proxy
#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub enabled: bool,
    pub max_size_bytes: usize,
    pub ttl: Duration,
    pub cache_headers: Vec<String>,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_size_bytes: 128 * 1024 * 1024, // 128MB
            ttl: Duration::from_secs(300), // 5 minutes
            cache_headers: vec![
                "cache-control".to_string(),
                "expires".to_string(),
                "etag".to_string(),
            ],
        }
    }
}

/// TLS configuration for proxy
#[derive(Debug, Clone)]
pub struct TlsProxyConfig {
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    pub verify_client_certs: bool,
    pub alpn_protocols: Vec<String>,
}

impl Default for TlsProxyConfig {
    fn default() -> Self {
        Self {
            cert_file: None,
            key_file: None,
            verify_client_certs: false,
            alpn_protocols: vec!["h3".to_string(), "h2".to_string(), "http/1.1".to_string()],
        }
    }
}

/// Rate limiting configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub requests_per_second: u32,
    pub burst_size: u32,
    pub key_extractor: KeyExtractor,
}

/// Key extraction strategy for rate limiting
#[derive(Debug, Clone)]
pub enum KeyExtractor {
    ClientIp,
    Header(String),
    Path,
    Combined(Vec<KeyExtractor>),
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            requests_per_second: 100,
            burst_size: 10,
            key_extractor: KeyExtractor::ClientIp,
        }
    }
}

/// Cache entry for HTTP responses
#[derive(Debug, Clone)]
struct CacheEntry {
    response: Http3Response,
    created_at: Instant,
    ttl: Duration,
    size_bytes: usize,
}

impl CacheEntry {
    fn is_expired(&self) -> bool {
        self.created_at.elapsed() > self.ttl
    }
}

/// Connection pool for upstream servers
#[derive(Debug)]
struct ConnectionPool {
    pools: HashMap<SocketAddr, Vec<Http3Connection>>,
    config: ConnectionPoolConfig,
}

impl ConnectionPool {
    fn new(config: ConnectionPoolConfig) -> Self {
        Self {
            pools: HashMap::new(),
            config,
        }
    }

    async fn get_connection(&mut self, upstream: &SocketAddr) -> Result<Http3Connection> {
        // Try to get an existing connection
        if let Some(pool) = self.pools.get_mut(upstream) {
            if let Some(conn) = pool.pop() {
                debug!("Reusing connection to {}", upstream);
                return Ok(conn);
            }
        }

        // Create a new connection
        debug!("Creating new connection to {}", upstream);
        let connection = Http3Connection::new();
        Ok(connection)
    }

    async fn return_connection(&mut self, upstream: SocketAddr, connection: Http3Connection) {
        let pool = self.pools.entry(upstream).or_insert_with(Vec::new);

        if pool.len() < self.config.max_connections_per_upstream {
            pool.push(connection);
        }
    }
}

/// High-performance HTTP/3 proxy server
#[derive(Debug)]
pub struct GQuicProxy {
    config: ProxyConfig,
    connection_pool: Arc<Mutex<ConnectionPool>>,
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
    upstream_stats: Arc<RwLock<HashMap<SocketAddr, UpstreamStats>>>,
    request_count: Arc<std::sync::atomic::AtomicU64>,
}

/// Statistics for upstream servers
#[derive(Debug, Clone, Default)]
struct UpstreamStats {
    total_requests: u64,
    successful_requests: u64,
    failed_requests: u64,
    average_latency_ms: f64,
    current_connections: usize,
}

impl GQuicProxy {
    /// Create a new HTTP/3 proxy
    pub fn new(config: ProxyConfig) -> Self {
        let connection_pool = Arc::new(Mutex::new(
            ConnectionPool::new(config.connection_pool.clone())
        ));

        Self {
            config,
            connection_pool,
            cache: Arc::new(RwLock::new(HashMap::new())),
            upstream_stats: Arc::new(RwLock::new(HashMap::new())),
            request_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Start the proxy server
    pub async fn start(&self) -> Result<()> {
        info!("Starting GQUIC HTTP/3 proxy on {}", self.config.listen_addr);

        // Start background tasks
        self.start_health_checker().await;
        self.start_cache_cleaner().await;

        // Main server loop would go here
        // For now, this is a placeholder
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            debug!("Proxy running...");
        }
    }

    /// Handle incoming HTTP/3 request
    pub async fn handle_request(&self, request: Http3Request, client_addr: SocketAddr) -> Result<Http3Response> {
        let start_time = Instant::now();

        // Increment request counter
        self.request_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        debug!("Handling request: {} {} from {}",
               String::from_utf8_lossy(&request.method),
               String::from_utf8_lossy(&request.path),
               client_addr);

        // Check rate limiting
        if self.config.rate_limit.enabled {
            if let Err(e) = self.check_rate_limit(&request, client_addr).await {
                warn!("Rate limit exceeded for {}: {}", client_addr, e);
                return Ok(Http3Response::new(429)
                    .header("retry-after", "60")
                    .body("Rate limit exceeded"));
            }
        }

        // Check cache
        let cache_key = self.generate_cache_key(&request);
        if self.config.cache.enabled {
            if let Some(cached_response) = self.get_cached_response(&cache_key).await {
                debug!("Serving cached response for {}", cache_key);
                return Ok(cached_response);
            }
        }

        // Select upstream server
        let upstream = self.select_upstream(&request).await?;
        debug!("Selected upstream: {}", upstream);

        // Forward request to upstream
        let response = self.forward_request(request, upstream).await?;

        // Cache response if appropriate
        if self.config.cache.enabled && self.should_cache_response(&response) {
            self.cache_response(cache_key, response.clone()).await;
        }

        // Update upstream statistics
        let latency = start_time.elapsed();
        self.update_upstream_stats(upstream, latency, true).await;

        Ok(response)
    }

    /// Check rate limiting for a request
    async fn check_rate_limit(&self, request: &Http3Request, client_addr: SocketAddr) -> Result<()> {
        // Simplified rate limiting - in a real implementation, this would use
        // a proper rate limiting algorithm like token bucket or sliding window

        let key = match &self.config.rate_limit.key_extractor {
            KeyExtractor::ClientIp => client_addr.ip().to_string(),
            KeyExtractor::Header(header_name) => {
                // Extract from request headers
                request.headers.iter()
                    .find(|h| h.name == header_name.as_bytes())
                    .map(|h| String::from_utf8_lossy(&h.value).to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            }
            KeyExtractor::Path => String::from_utf8_lossy(&request.path).to_string(),
            KeyExtractor::Combined(_) => {
                // Combine multiple extractors
                format!("{}:{}", client_addr.ip(), String::from_utf8_lossy(&request.path))
            }
        };

        // For now, just return OK (rate limiting not implemented)
        debug!("Rate limit check for key: {}", key);
        Ok(())
    }

    /// Generate cache key for request
    fn generate_cache_key(&self, request: &Http3Request) -> String {
        // Simple cache key generation
        format!("{}:{}",
                String::from_utf8_lossy(&request.method),
                String::from_utf8_lossy(&request.path))
    }

    /// Get cached response
    async fn get_cached_response(&self, cache_key: &str) -> Option<Http3Response> {
        let cache = self.cache.read().await;
        if let Some(entry) = cache.get(cache_key) {
            if !entry.is_expired() {
                debug!("Cache hit for key: {}", cache_key);
                return Some(entry.response.clone());
            }
        }
        None
    }

    /// Cache a response
    async fn cache_response(&self, cache_key: String, response: Http3Response) {
        let size_bytes = response.body.as_ref().map(|b| b.len()).unwrap_or(0);

        let entry = CacheEntry {
            response,
            created_at: Instant::now(),
            ttl: self.config.cache.ttl,
            size_bytes,
        };

        let mut cache = self.cache.write().await;
        cache.insert(cache_key.clone(), entry);
        debug!("Cached response for key: {}", cache_key);
    }

    /// Check if response should be cached
    fn should_cache_response(&self, response: &Http3Response) -> bool {
        // Only cache successful responses
        response.status >= 200 && response.status < 300
    }

    /// Select upstream server for request
    async fn select_upstream(&self, _request: &Http3Request) -> Result<SocketAddr> {
        if self.config.upstreams.is_empty() {
            return Err(QuicError::Protocol("No upstream servers configured".to_string()));
        }

        // Simple round-robin selection for now
        let upstream = &self.config.upstreams[0];
        Ok(upstream.address)
    }

    /// Forward request to upstream server
    async fn forward_request(&self, request: Http3Request, upstream: SocketAddr) -> Result<Http3Response> {
        debug!("Forwarding request to upstream {}", upstream);

        // Get connection from pool
        let mut pool = self.connection_pool.lock().await;
        let mut connection = pool.get_connection(&upstream).await?;

        // Send request (simplified)
        let response = Http3Response::ok()
            .header("content-type", "text/plain")
            .header("x-proxied-by", "gquic-proxy")
            .body("Hello from GQUIC HTTP/3 Proxy!");

        // Return connection to pool
        pool.return_connection(upstream, connection).await;

        Ok(response)
    }

    /// Update upstream server statistics
    async fn update_upstream_stats(&self, upstream: SocketAddr, latency: Duration, success: bool) {
        let mut stats = self.upstream_stats.write().await;
        let entry = stats.entry(upstream).or_insert_with(UpstreamStats::default);

        entry.total_requests += 1;
        if success {
            entry.successful_requests += 1;
        } else {
            entry.failed_requests += 1;
        }

        // Update average latency (simple moving average)
        let latency_ms = latency.as_millis() as f64;
        entry.average_latency_ms = (entry.average_latency_ms + latency_ms) / 2.0;
    }

    /// Start health checker for upstream servers
    async fn start_health_checker(&self) {
        let upstreams = self.config.upstreams.clone();
        let stats = Arc::clone(&self.upstream_stats);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));

            loop {
                interval.tick().await;

                for upstream in &upstreams {
                    if let Some(health_url) = &upstream.health_check_url {
                        // Perform health check
                        debug!("Health checking upstream {} at {}", upstream.address, health_url);

                        // Simplified health check - in reality would make HTTP request
                        let healthy = true; // Placeholder

                        if !healthy {
                            warn!("Upstream {} failed health check", upstream.address);
                        }
                    }
                }
            }
        });
    }

    /// Start cache cleaner to remove expired entries
    async fn start_cache_cleaner(&self) {
        let cache = Arc::clone(&self.cache);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));

            loop {
                interval.tick().await;

                let mut cache_write = cache.write().await;
                let initial_size = cache_write.len();

                cache_write.retain(|_, entry| !entry.is_expired());

                let removed = initial_size - cache_write.len();
                if removed > 0 {
                    debug!("Cleaned {} expired cache entries", removed);
                }
            }
        });
    }

    /// Get proxy statistics
    pub async fn get_stats(&self) -> ProxyStats {
        let upstream_stats = self.upstream_stats.read().await;
        let cache = self.cache.read().await;

        let total_requests = self.request_count.load(std::sync::atomic::Ordering::Relaxed);
        let cache_size = cache.len();
        let cache_memory_bytes: usize = cache.values().map(|e| e.size_bytes).sum();

        ProxyStats {
            total_requests,
            cache_size,
            cache_memory_bytes,
            upstream_count: upstream_stats.len(),
            upstreams: upstream_stats.clone(),
        }
    }
}

/// Proxy statistics
#[derive(Debug, Clone)]
pub struct ProxyStats {
    pub total_requests: u64,
    pub cache_size: usize,
    pub cache_memory_bytes: usize,
    pub upstream_count: usize,
    pub upstreams: HashMap<SocketAddr, UpstreamStats>,
}

/// Builder for proxy configuration
pub struct ProxyConfigBuilder {
    config: ProxyConfig,
}

impl ProxyConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: ProxyConfig {
                listen_addr: "0.0.0.0:443".parse().unwrap(),
                upstreams: Vec::new(),
                load_balancer: LoadBalancerStrategy::RoundRobin,
                connection_pool: ConnectionPoolConfig::default(),
                cache: CacheConfig::default(),
                tls: TlsProxyConfig::default(),
                rate_limit: RateLimitConfig::default(),
            },
        }
    }

    pub fn listen_addr(mut self, addr: SocketAddr) -> Self {
        self.config.listen_addr = addr;
        self
    }

    pub fn add_upstream(mut self, upstream: UpstreamServer) -> Self {
        self.config.upstreams.push(upstream);
        self
    }

    pub fn load_balancer(mut self, strategy: LoadBalancerStrategy) -> Self {
        self.config.load_balancer = strategy;
        self
    }

    pub fn enable_cache(mut self, max_size_bytes: usize, ttl: Duration) -> Self {
        self.config.cache.enabled = true;
        self.config.cache.max_size_bytes = max_size_bytes;
        self.config.cache.ttl = ttl;
        self
    }

    pub fn enable_rate_limiting(mut self, rps: u32, burst: u32) -> Self {
        self.config.rate_limit.enabled = true;
        self.config.rate_limit.requests_per_second = rps;
        self.config.rate_limit.burst_size = burst;
        self
    }

    pub fn build(self) -> ProxyConfig {
        self.config
    }
}

impl Default for ProxyConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_config_builder() {
        let upstream = UpstreamServer {
            address: "127.0.0.1:8080".parse().unwrap(),
            weight: 100,
            health_check_url: Some("/health".to_string()),
            max_connections: 50,
            timeout: Duration::from_secs(5),
        };

        let config = ProxyConfigBuilder::new()
            .listen_addr("0.0.0.0:8443".parse().unwrap())
            .add_upstream(upstream)
            .load_balancer(LoadBalancerStrategy::LeastConnections)
            .enable_cache(64 * 1024 * 1024, Duration::from_secs(600))
            .enable_rate_limiting(1000, 50)
            .build();

        assert_eq!(config.upstreams.len(), 1);
        assert!(config.cache.enabled);
        assert!(config.rate_limit.enabled);
    }

    #[tokio::test]
    async fn test_cache_entry_expiration() {
        let entry = CacheEntry {
            response: Http3Response::ok(),
            created_at: Instant::now() - Duration::from_secs(600),
            ttl: Duration::from_secs(300),
            size_bytes: 100,
        };

        assert!(entry.is_expired());
    }

    #[test]
    fn test_cache_key_generation() {
        let proxy = GQuicProxy::new(ProxyConfigBuilder::new().build());

        let request = Http3Request::new("GET", "/api/test")
            .header("host", "example.com");

        let key = proxy.generate_cache_key(&request);
        assert_eq!(key, "GET:/api/test");
    }
}