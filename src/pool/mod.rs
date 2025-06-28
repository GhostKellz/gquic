use dashmap::DashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::time::interval;
use tracing::{debug, info};

use crate::quic::Connection;

pub mod config;
pub use config::PoolConfig;

#[derive(Debug, Clone)]
pub struct PooledConnection {
    pub connection: Connection,
    pub created_at: Instant,
    pub last_used: Instant,
    pub use_count: u64,
}

impl PooledConnection {
    pub fn new(connection: Connection) -> Self {
        let now = Instant::now();
        Self {
            connection,
            created_at: now,
            last_used: now,
            use_count: 0,
        }
    }

    pub fn touch(&mut self) {
        self.last_used = Instant::now();
        self.use_count += 1;
    }

    pub fn is_expired(&self, max_age: Duration) -> bool {
        self.created_at.elapsed() > max_age
    }

    pub fn is_idle(&self, max_idle: Duration) -> bool {
        self.last_used.elapsed() > max_idle
    }

    pub async fn is_closed(&self) -> bool {
        // Check if connection is closed using our QUIC implementation
        use crate::quic::ConnectionState;
        matches!(self.connection.state().await, ConnectionState::Closed | ConnectionState::Failed)
    }
}

#[derive(Debug)]
pub struct ConnectionPool {
    connections: DashMap<SocketAddr, Vec<PooledConnection>>,
    config: PoolConfig,
}

impl ConnectionPool {
    pub fn new(config: PoolConfig) -> Self {
        let pool = Self {
            connections: DashMap::new(),
            config,
        };

        // Start cleanup task
        let pool_clone = pool.clone();
        tokio::spawn(async move {
            pool_clone.cleanup_task().await;
        });

        pool
    }

    pub async fn get_connection(&self, addr: SocketAddr) -> Option<Connection> {
        let mut entry = self.connections.entry(addr).or_insert_with(Vec::new);
        let connections = entry.value_mut();

        // Find a healthy connection
        while let Some(mut pooled) = connections.pop() {
            if !pooled.is_closed().await && !pooled.is_expired(self.config.max_connection_age) {
                pooled.touch();
                let conn = pooled.connection.clone();
                connections.push(pooled);
                debug!("Reusing connection to {}", addr);
                return Some(conn);
            }
        }

        None
    }

    pub async fn return_connection(&self, addr: SocketAddr, connection: Connection) {
        if connection.state().await == crate::quic::ConnectionState::Closed {
            debug!("Not returning closed connection to pool");
            return;
        }

        let mut entry = self.connections.entry(addr).or_insert_with(Vec::new);
        let connections = entry.value_mut();

        if connections.len() >= self.config.max_connections_per_endpoint as usize {
            debug!("Pool full for {}, not returning connection", addr);
            return;
        }

        let pooled = PooledConnection::new(connection);
        connections.push(pooled);
        debug!("Returned connection to pool for {}", addr);
    }

    pub fn pool_stats(&self) -> PoolStats {
        let mut total_connections = 0;
        let mut endpoints = 0;

        for entry in self.connections.iter() {
            endpoints += 1;
            total_connections += entry.value().len();
        }

        PoolStats {
            total_connections,
            endpoints,
            max_connections_per_endpoint: self.config.max_connections_per_endpoint,
        }
    }

    async fn cleanup_task(&self) {
        let mut cleanup_interval = interval(self.config.cleanup_interval);

        loop {
            cleanup_interval.tick().await;
            self.cleanup_expired_connections().await;
        }
    }

    async fn cleanup_expired_connections(&self) {
        let mut total_removed = 0;

        // Note: DashMap doesn't have async retain, so we need to collect and remove separately
        let mut to_remove = Vec::new();
        
        for mut entry in self.connections.iter_mut() {
            let addr = *entry.key();
            let connections = entry.value_mut();
            let initial_len = connections.len();
            
            // Create a new vector with only valid connections
            let mut valid_connections = Vec::new();
            for pooled in connections.drain(..) {
                if !pooled.is_closed().await 
                    && !pooled.is_expired(self.config.max_connection_age)
                    && !pooled.is_idle(self.config.max_idle_time) {
                    valid_connections.push(pooled);
                }
            }

            let removed = initial_len - valid_connections.len();
            total_removed += removed;

            if removed > 0 {
                debug!("Cleaned up {} expired connections for {}", removed, addr);
            }

            if valid_connections.is_empty() {
                to_remove.push(addr);
            } else {
                *connections = valid_connections;
            }
        }

        // Remove empty entries
        for addr in to_remove {
            self.connections.remove(&addr);
        }

        if total_removed > 0 {
            info!("Pool cleanup: removed {} expired connections", total_removed);
        }
    }
}

impl Clone for ConnectionPool {
    fn clone(&self) -> Self {
        Self {
            connections: self.connections.clone(),
            config: self.config.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PoolStats {
    pub total_connections: usize,
    pub endpoints: usize,
    pub max_connections_per_endpoint: u32,
}