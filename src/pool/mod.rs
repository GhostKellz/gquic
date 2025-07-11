//! Connection pooling and resource management for QUIC
//! 
//! This module provides connection pooling, resource management,
//! and efficient connection reuse for QUIC connections.

use crate::quic::{
    connection::Connection,
    error::{QuicError, Result},
};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Semaphore, Mutex};
use tokio::time::{sleep, timeout};
use tracing::{debug, info, warn, error, instrument};

/// Connection pool configuration
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Maximum number of connections per endpoint
    pub max_connections_per_endpoint: usize,
    /// Maximum total connections in the pool
    pub max_total_connections: usize,
    /// Minimum number of idle connections to maintain
    pub min_idle_connections: usize,
    /// Maximum time a connection can be idle before being closed
    pub max_idle_time: Duration,
    /// Connection timeout
    pub connection_timeout: Duration,
    /// How often to check for expired connections
    pub cleanup_interval: Duration,
    /// Whether to validate connections before use
    pub validate_on_borrow: bool,
    /// Whether to validate connections when returned
    pub validate_on_return: bool,
    /// Maximum number of times to retry connection creation
    pub max_retries: usize,
    /// Enable connection health checks
    pub health_checks: bool,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections_per_endpoint: 100,
            max_total_connections: 1000,
            min_idle_connections: 10,
            max_idle_time: Duration::from_secs(300), // 5 minutes
            connection_timeout: Duration::from_secs(30),
            cleanup_interval: Duration::from_secs(60),
            validate_on_borrow: true,
            validate_on_return: false,
            max_retries: 3,
            health_checks: true,
        }
    }
}

/// Pooled connection wrapper
#[derive(Debug)]
pub struct PooledConnection {
    /// The actual QUIC connection
    pub connection: Connection,
    /// When this connection was created
    created_at: Instant,
    /// When this connection was last used
    last_used: Instant,
    /// How many times this connection has been used
    use_count: u64,
    /// Whether this connection is currently in use
    in_use: bool,
    /// Remote endpoint address
    remote_addr: SocketAddr,
    /// Connection health status
    health_status: ConnectionHealth,
}

/// Connection health status
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionHealth {
    /// Connection is healthy and ready to use
    Healthy,
    /// Connection is degraded but still usable
    Degraded,
    /// Connection is unhealthy and should be closed
    Unhealthy,
}

impl PooledConnection {
    /// Create a new pooled connection
    pub fn new(connection: Connection, remote_addr: SocketAddr) -> Self {
        let now = Instant::now();
        Self {
            connection,
            created_at: now,
            last_used: now,
            use_count: 0,
            in_use: false,
            remote_addr,
            health_status: ConnectionHealth::Healthy,
        }
    }
    
    /// Check if this connection is expired
    pub fn is_expired(&self, max_idle_time: Duration) -> bool {
        !self.in_use && self.last_used.elapsed() > max_idle_time
    }
    
    /// Mark connection as used
    pub fn mark_used(&mut self) {
        self.last_used = Instant::now();
        self.use_count += 1;
        self.in_use = true;
    }
    
    /// Mark connection as returned
    pub fn mark_returned(&mut self) {
        self.in_use = false;
    }
    
    /// Check connection health
    pub async fn check_health(&mut self) -> ConnectionHealth {
        // Simple health check - in real implementation, this would ping the connection
        match self.connection.state().await {
            crate::quic::connection::ConnectionState::Connected => {
                self.health_status = ConnectionHealth::Healthy;
            }
            crate::quic::connection::ConnectionState::Closing | 
            crate::quic::connection::ConnectionState::Closed => {
                self.health_status = ConnectionHealth::Unhealthy;
            }
            _ => {
                self.health_status = ConnectionHealth::Degraded;
            }
        }
        
        self.health_status.clone()
    }
}

/// Connection pool statistics
#[derive(Debug, Clone)]
pub struct PoolStats {
    /// Total number of connections in the pool
    pub total_connections: usize,
    /// Number of active (in-use) connections
    pub active_connections: usize,
    /// Number of idle connections
    pub idle_connections: usize,
    /// Number of connections per endpoint
    pub connections_per_endpoint: HashMap<SocketAddr, usize>,
    /// Total connections created
    pub total_created: u64,
    /// Total connections destroyed
    pub total_destroyed: u64,
    /// Total connection requests
    pub total_requests: u64,
    /// Total connection timeouts
    pub total_timeouts: u64,
    /// Average connection age
    pub avg_connection_age: Duration,
    /// Pool utilization percentage
    pub utilization: f64,
}

/// QUIC connection pool
pub struct ConnectionPool {
    /// Pool configuration
    config: PoolConfig,
    /// Connections grouped by endpoint
    connections: Arc<RwLock<HashMap<SocketAddr, VecDeque<PooledConnection>>>>,
    /// Connection creation semaphore
    creation_semaphore: Arc<Semaphore>,
    /// Pool statistics
    stats: Arc<RwLock<PoolStats>>,
    /// Cleanup task handle
    cleanup_handle: Option<tokio::task::JoinHandle<()>>,
}

impl ConnectionPool {
    /// Create a new connection pool
    pub fn new(config: PoolConfig) -> Self {
        let pool = Self {
            creation_semaphore: Arc::new(Semaphore::new(config.max_total_connections)),
            stats: Arc::new(RwLock::new(PoolStats {
                total_connections: 0,
                active_connections: 0,
                idle_connections: 0,
                connections_per_endpoint: HashMap::new(),
                total_created: 0,
                total_destroyed: 0,
                total_requests: 0,
                total_timeouts: 0,
                avg_connection_age: Duration::from_secs(0),
                utilization: 0.0,
            })),
            connections: Arc::new(RwLock::new(HashMap::new())),
            config,
            cleanup_handle: None,
        };
        
        pool
    }
    
    /// Start the connection pool with background cleanup
    pub async fn start(&mut self) -> Result<()> {
        let connections = self.connections.clone();
        let stats = self.stats.clone();
        let cleanup_interval = self.config.cleanup_interval;
        let max_idle_time = self.config.max_idle_time;
        
        let cleanup_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(cleanup_interval);
            
            loop {
                interval.tick().await;
                
                if let Err(e) = Self::cleanup_expired_connections(
                    connections.clone(),
                    stats.clone(),
                    max_idle_time,
                ).await {
                    error!("Failed to cleanup expired connections: {}", e);
                }
            }
        });
        
        self.cleanup_handle = Some(cleanup_handle);
        info!("Connection pool started");
        Ok(())
    }
    
    /// Get a connection from the pool
    #[instrument(skip(self))]
    pub async fn get_connection(&self, remote_addr: SocketAddr) -> Result<PooledConnection> {
        let mut stats = self.stats.write().await;
        stats.total_requests += 1;
        drop(stats);
        
        // Try to get an existing connection first
        if let Some(mut conn) = self.try_get_existing_connection(remote_addr).await? {
            // Validate connection if configured
            if self.config.validate_on_borrow {
                if conn.check_health().await == ConnectionHealth::Unhealthy {
                    debug!("Connection validation failed, creating new connection");
                    return self.create_new_connection(remote_addr).await;
                }
            }
            
            conn.mark_used();
            debug!("Reused existing connection to {}", remote_addr);
            return Ok(conn);
        }
        
        // Create a new connection
        self.create_new_connection(remote_addr).await
    }
    
    /// Try to get an existing connection from the pool
    async fn try_get_existing_connection(&self, remote_addr: SocketAddr) -> Result<Option<PooledConnection>> {
        let mut connections = self.connections.write().await;
        
        if let Some(endpoint_connections) = connections.get_mut(&remote_addr) {
            while let Some(mut conn) = endpoint_connections.pop_front() {
                if !conn.is_expired(self.config.max_idle_time) {
                    return Ok(Some(conn));
                } else {
                    // Connection expired, close it
                    if let Err(e) = conn.connection.close(0, "Connection expired").await {
                        warn!("Failed to close expired connection: {}", e);
                    }
                    
                    // Update stats
                    let mut stats = self.stats.write().await;
                    stats.total_destroyed += 1;
                    stats.total_connections -= 1;
                    stats.idle_connections -= 1;
                }
            }
        }
        
        Ok(None)
    }
    
    /// Create a new connection
    async fn create_new_connection(&self, remote_addr: SocketAddr) -> Result<PooledConnection> {
        // Check if we can create a new connection
        let permit = timeout(
            self.config.connection_timeout,
            self.creation_semaphore.acquire(),
        ).await
        .map_err(|_| QuicError::Config("Connection creation timeout".to_string()))?
        .map_err(|_| QuicError::Config("Failed to acquire connection permit".to_string()))?;
        
        // Check per-endpoint limit
        {
            let connections = self.connections.read().await;
            if let Some(endpoint_connections) = connections.get(&remote_addr) {
                if endpoint_connections.len() >= self.config.max_connections_per_endpoint {
                    return Err(QuicError::Config("Too many connections to endpoint".to_string()));
                }
            }
        }
        
        // Create the connection with retries
        let mut last_error = None;
        for attempt in 0..self.config.max_retries {
            match self.create_connection_with_retry(remote_addr, attempt).await {
                Ok(connection) => {
                    let pooled_conn = PooledConnection::new(connection, remote_addr);
                    
                    // Update stats
                    let mut stats = self.stats.write().await;
                    stats.total_created += 1;
                    stats.total_connections += 1;
                    stats.active_connections += 1;
                    
                    // Update per-endpoint stats
                    *stats.connections_per_endpoint.entry(remote_addr).or_insert(0) += 1;
                    
                    debug!("Created new connection to {} (attempt {})", remote_addr, attempt + 1);
                    return Ok(pooled_conn);
                }
                Err(e) => {
                    last_error = Some(e);
                    if attempt < self.config.max_retries - 1 {
                        let backoff = Duration::from_millis(100 * (2_u64.pow(attempt as u32)));
                        sleep(backoff).await;
                    }
                }
            }
        }
        
        drop(permit);
        Err(last_error.unwrap_or_else(|| QuicError::Config("Failed to create connection".to_string())))
    }
    
    /// Create a connection with retry logic
    async fn create_connection_with_retry(&self, remote_addr: SocketAddr, attempt: usize) -> Result<Connection> {
        // This is a simplified implementation
        // In a real implementation, this would use the actual QUIC endpoint to create connections
        debug!("Creating connection to {} (attempt {})", remote_addr, attempt + 1);
        
        // Simulate connection creation
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // For now, return an error to simulate creation failure
        Err(QuicError::Config("Connection creation not implemented".to_string()))
    }
    
    /// Return a connection to the pool
    #[instrument(skip(self, mut connection))]
    pub async fn return_connection(&self, mut connection: PooledConnection) -> Result<()> {
        // Validate connection if configured
        if self.config.validate_on_return {
            if connection.check_health().await == ConnectionHealth::Unhealthy {
                debug!("Connection validation failed on return, closing connection");
                if let Err(e) = connection.connection.close(0, "Connection unhealthy").await {
                    warn!("Failed to close unhealthy connection: {}", e);
                }
                return Ok(());
            }
        }
        
        connection.mark_returned();
        
        // Add back to pool
        let mut connections = self.connections.write().await;
        connections.entry(connection.remote_addr)
            .or_insert_with(VecDeque::new)
            .push_back(connection);
        
        // Update stats
        let mut stats = self.stats.write().await;
        stats.active_connections -= 1;
        stats.idle_connections += 1;
        
        debug!("Connection returned to pool for {}", connection.remote_addr);
        Ok(())
    }
    
    /// Get pool statistics
    pub async fn get_stats(&self) -> PoolStats {
        let stats = self.stats.read().await;
        let mut stats_copy = stats.clone();
        
        // Calculate utilization
        if self.config.max_total_connections > 0 {
            stats_copy.utilization = (stats_copy.total_connections as f64 / self.config.max_total_connections as f64) * 100.0;
        }
        
        stats_copy
    }
    
    /// Clean up expired connections
    async fn cleanup_expired_connections(
        connections: Arc<RwLock<HashMap<SocketAddr, VecDeque<PooledConnection>>>>,
        stats: Arc<RwLock<PoolStats>>,
        max_idle_time: Duration,
    ) -> Result<()> {
        let mut connections_guard = connections.write().await;
        let mut expired_count = 0;
        
        for (addr, endpoint_connections) in connections_guard.iter_mut() {
            let initial_len = endpoint_connections.len();
            
            // Remove expired connections
            endpoint_connections.retain(|conn| {
                if conn.is_expired(max_idle_time) {
                    expired_count += 1;
                    false
                } else {
                    true
                }
            });
            
            let removed = initial_len - endpoint_connections.len();
            if removed > 0 {
                debug!("Cleaned up {} expired connections for {}", removed, addr);
            }
        }
        
        // Remove empty endpoint entries
        connections_guard.retain(|_, connections| !connections.is_empty());
        
        if expired_count > 0 {
            // Update stats
            let mut stats_guard = stats.write().await;
            stats_guard.total_destroyed += expired_count;
            stats_guard.total_connections -= expired_count as usize;
            stats_guard.idle_connections -= expired_count as usize;
            
            info!("Cleaned up {} expired connections", expired_count);
        }
        
        Ok(())
    }
    
    /// Close all connections and shutdown the pool
    pub async fn shutdown(&mut self) -> Result<()> {
        info!("Shutting down connection pool");
        
        // Cancel cleanup task
        if let Some(handle) = self.cleanup_handle.take() {
            handle.abort();
        }
        
        // Close all connections
        let mut connections = self.connections.write().await;
        let mut closed_count = 0;
        
        for (addr, endpoint_connections) in connections.iter_mut() {
            for conn in endpoint_connections.iter_mut() {
                if let Err(e) = conn.connection.close(0, "Pool shutdown").await {
                    warn!("Failed to close connection to {}: {}", addr, e);
                } else {
                    closed_count += 1;
                }
            }
        }
        
        connections.clear();
        
        // Reset stats
        let mut stats = self.stats.write().await;
        stats.total_connections = 0;
        stats.active_connections = 0;
        stats.idle_connections = 0;
        stats.connections_per_endpoint.clear();
        
        info!("Connection pool shutdown complete. Closed {} connections", closed_count);
        Ok(())
    }
}

/// Connection pool manager for multiple pools
pub struct PoolManager {
    pools: HashMap<String, ConnectionPool>,
}

impl PoolManager {
    /// Create a new pool manager
    pub fn new() -> Self {
        Self {
            pools: HashMap::new(),
        }
    }
    
    /// Add a connection pool
    pub fn add_pool(&mut self, name: String, pool: ConnectionPool) {
        self.pools.insert(name, pool);
    }
    
    /// Get a connection pool by name
    pub fn get_pool(&self, name: &str) -> Option<&ConnectionPool> {
        self.pools.get(name)
    }
    
    /// Get a mutable reference to a connection pool
    pub fn get_pool_mut(&mut self, name: &str) -> Option<&mut ConnectionPool> {
        self.pools.get_mut(name)
    }
    
    /// Start all pools
    pub async fn start_all(&mut self) -> Result<()> {
        for (name, pool) in self.pools.iter_mut() {
            if let Err(e) = pool.start().await {
                error!("Failed to start pool '{}': {}", name, e);
                return Err(e);
            }
        }
        
        info!("Started {} connection pools", self.pools.len());
        Ok(())
    }
    
    /// Shutdown all pools
    pub async fn shutdown_all(&mut self) -> Result<()> {
        for (name, pool) in self.pools.iter_mut() {
            if let Err(e) = pool.shutdown().await {
                error!("Failed to shutdown pool '{}': {}", name, e);
            }
        }
        
        info!("Shutdown {} connection pools", self.pools.len());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    
    #[tokio::test]
    async fn test_pool_config_default() {
        let config = PoolConfig::default();
        assert_eq!(config.max_connections_per_endpoint, 100);
        assert_eq!(config.max_total_connections, 1000);
        assert_eq!(config.min_idle_connections, 10);
    }
    
    #[tokio::test]
    async fn test_pooled_connection_expiry() {
        let addr = SocketAddr::from_str("127.0.0.1:443").unwrap();
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let connection = crate::quic::connection::Connection::new(
            crate::quic::connection::ConnectionId::new(),
            addr,
            socket,
            true,
        );
        
        let mut pooled = PooledConnection::new(connection, addr);
        
        // Connection should not be expired initially
        assert!(!pooled.is_expired(Duration::from_secs(60)));
        
        // Simulate time passing
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // Connection should be expired with very short timeout
        assert!(pooled.is_expired(Duration::from_millis(50)));
    }
    
    #[tokio::test]
    async fn test_connection_pool_creation() {
        let config = PoolConfig::default();
        let pool = ConnectionPool::new(config);
        
        let stats = pool.get_stats().await;
        assert_eq!(stats.total_connections, 0);
        assert_eq!(stats.active_connections, 0);
        assert_eq!(stats.idle_connections, 0);
    }
    
    #[tokio::test]
    async fn test_pool_manager() {
        let mut manager = PoolManager::new();
        let pool = ConnectionPool::new(PoolConfig::default());
        
        manager.add_pool("default".to_string(), pool);
        
        assert!(manager.get_pool("default").is_some());
        assert!(manager.get_pool("nonexistent").is_none());
    }
}