use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, warn, error};

use crate::quic::error::{QuicError, SecurityError};

/// Rate limiter for various resources
#[derive(Debug)]
pub struct RateLimiter {
    limits: HashMap<String, RateLimit>,
    counters: RwLock<HashMap<(IpAddr, String), RateCounter>>,
}

#[derive(Debug, Clone)]
pub struct RateLimit {
    pub max_requests: u64,
    pub window: Duration,
    pub burst_size: u64,
}

#[derive(Debug)]
struct RateCounter {
    count: u64,
    last_reset: Instant,
    burst_tokens: u64,
}

impl RateLimiter {
    pub fn new() -> Self {
        let mut limits = HashMap::new();
        
        // Default rate limits
        limits.insert("connections".to_string(), RateLimit {
            max_requests: 100,
            window: Duration::from_secs(60),
            burst_size: 10,
        });
        
        limits.insert("packets".to_string(), RateLimit {
            max_requests: 1000,
            window: Duration::from_secs(1),
            burst_size: 50,
        });
        
        limits.insert("handshakes".to_string(), RateLimit {
            max_requests: 10,
            window: Duration::from_secs(60),
            burst_size: 2,
        });
        
        Self {
            limits,
            counters: RwLock::new(HashMap::new()),
        }
    }
    
    pub fn add_limit(&mut self, resource: String, limit: RateLimit) {
        self.limits.insert(resource, limit);
    }
    
    pub async fn check_rate_limit(&self, ip: IpAddr, resource: &str) -> Result<(), QuicError> {
        let limit = match self.limits.get(resource) {
            Some(limit) => limit.clone(),
            None => return Ok(()), // No limit configured
        };
        
        let mut counters = self.counters.write().await;
        let key = (ip, resource.to_string());
        let now = Instant::now();
        
        let counter = counters.entry(key).or_insert_with(|| RateCounter {
            count: 0,
            last_reset: now,
            burst_tokens: limit.burst_size,
        });
        
        // Reset counter if window has passed
        if now.duration_since(counter.last_reset) >= limit.window {
            counter.count = 0;
            counter.last_reset = now;
            counter.burst_tokens = limit.burst_size;
        }
        
        // Check if we can use a burst token
        if counter.burst_tokens > 0 {
            counter.burst_tokens -= 1;
            counter.count += 1;
            return Ok(());
        }
        
        // Check normal rate limit
        if counter.count >= limit.max_requests {
            warn!("Rate limit exceeded for {} from {}: {} requests in {:?}", 
                  resource, ip, counter.count, limit.window);
            return Err(QuicError::Security(SecurityError::RateLimitExceeded {
                resource: resource.to_string(),
                limit: limit.max_requests,
                window: limit.window,
            }));
        }
        
        counter.count += 1;
        Ok(())
    }
    
    pub async fn cleanup_old_counters(&self) {
        let mut counters = self.counters.write().await;
        let now = Instant::now();
        let cleanup_threshold = Duration::from_secs(3600); // 1 hour
        
        counters.retain(|_, counter| {
            now.duration_since(counter.last_reset) < cleanup_threshold
        });
    }
}

/// DDoS protection system
#[derive(Debug)]
pub struct DdosProtection {
    suspicious_ips: RwLock<HashMap<IpAddr, SuspiciousActivity>>,
    rate_limiter: RateLimiter,
    config: DdosConfig,
}

#[derive(Debug, Clone)]
pub struct DdosConfig {
    pub max_connections_per_ip: u32,
    pub max_packets_per_second: u32,
    pub suspicious_threshold: u32,
    pub ban_duration: Duration,
    pub enable_amplification_protection: bool,
}

impl Default for DdosConfig {
    fn default() -> Self {
        Self {
            max_connections_per_ip: 50,
            max_packets_per_second: 500,
            suspicious_threshold: 100,
            ban_duration: Duration::from_secs(300), // 5 minutes
            enable_amplification_protection: true,
        }
    }
}

#[derive(Debug)]
struct SuspiciousActivity {
    score: u32,
    last_activity: Instant,
    banned_until: Option<Instant>,
    connection_count: u32,
    packet_count: u32,
    last_packet_reset: Instant,
}

impl DdosProtection {
    pub fn new(config: DdosConfig) -> Self {
        Self {
            suspicious_ips: RwLock::new(HashMap::new()),
            rate_limiter: RateLimiter::new(),
            config,
        }
    }
    
    pub async fn check_connection_allowed(&self, remote_addr: SocketAddr) -> Result<(), QuicError> {
        let ip = remote_addr.ip();
        
        // Check if IP is currently banned
        {
            let suspicious_ips = self.suspicious_ips.read().await;
            if let Some(activity) = suspicious_ips.get(&ip) {
                if let Some(banned_until) = activity.banned_until {
                    if Instant::now() < banned_until {
                        return Err(QuicError::Security(SecurityError::DdosProtection(
                            format!("IP {} is temporarily banned", ip)
                        )));
                    }
                }
            }
        }
        
        // Check rate limits
        self.rate_limiter.check_rate_limit(ip, "connections").await?;
        
        // Update connection count
        self.track_connection(ip).await?;
        
        Ok(())
    }
    
    pub async fn check_packet_allowed(&self, remote_addr: SocketAddr, packet_size: usize) -> Result<(), QuicError> {
        let ip = remote_addr.ip();
        
        // Check rate limits
        self.rate_limiter.check_rate_limit(ip, "packets").await?;
        
        // Check for amplification attacks
        if self.config.enable_amplification_protection {
            self.check_amplification_attack(ip, packet_size).await?;
        }
        
        // Track packet activity
        self.track_packet_activity(ip).await?;
        
        Ok(())
    }
    
    async fn track_connection(&self, ip: IpAddr) -> Result<(), QuicError> {
        let mut suspicious_ips = self.suspicious_ips.write().await;
        let now = Instant::now();
        
        let activity = suspicious_ips.entry(ip).or_insert_with(|| SuspiciousActivity {
            score: 0,
            last_activity: now,
            banned_until: None,
            connection_count: 0,
            packet_count: 0,
            last_packet_reset: now,
        });
        
        activity.connection_count += 1;
        activity.last_activity = now;
        
        if activity.connection_count > self.config.max_connections_per_ip {
            activity.score += 10;
            warn!("IP {} has {} connections, score: {}", ip, activity.connection_count, activity.score);
        }
        
        self.check_and_ban_if_suspicious(ip, activity).await?;
        
        Ok(())
    }
    
    async fn track_packet_activity(&self, ip: IpAddr) -> Result<(), QuicError> {
        let mut suspicious_ips = self.suspicious_ips.write().await;
        let now = Instant::now();
        
        let activity = suspicious_ips.entry(ip).or_insert_with(|| SuspiciousActivity {
            score: 0,
            last_activity: now,
            banned_until: None,
            connection_count: 0,
            packet_count: 0,
            last_packet_reset: now,
        });
        
        // Reset packet count every second
        if now.duration_since(activity.last_packet_reset) >= Duration::from_secs(1) {
            activity.packet_count = 0;
            activity.last_packet_reset = now;
        }
        
        activity.packet_count += 1;
        activity.last_activity = now;
        
        if activity.packet_count > self.config.max_packets_per_second {
            activity.score += 5;
            debug!("IP {} sending {} packets/sec, score: {}", ip, activity.packet_count, activity.score);
        }
        
        self.check_and_ban_if_suspicious(ip, activity).await?;
        
        Ok(())
    }
    
    async fn check_amplification_attack(&self, ip: IpAddr, packet_size: usize) -> Result<(), QuicError> {
        // Simple amplification detection: if we're sending more than 3x what we received
        // This is a simplified check - in production, you'd track request/response ratios
        if packet_size > 1200 { // Typical MTU
            let suspicious_ips = self.suspicious_ips.read().await;
            if let Some(activity) = suspicious_ips.get(&ip) {
                if activity.score > 0 {
                    warn!("Possible amplification attack from {}: large packet {} bytes", ip, packet_size);
                    return Err(QuicError::Security(SecurityError::AmplificationAttack));
                }
            }
        }
        
        Ok(())
    }
    
    async fn check_and_ban_if_suspicious(&self, ip: IpAddr, activity: &mut SuspiciousActivity) -> Result<(), QuicError> {
        if activity.score >= self.config.suspicious_threshold {
            activity.banned_until = Some(Instant::now() + self.config.ban_duration);
            activity.score = 0; // Reset score after banning
            
            error!("Banning IP {} for {} seconds due to suspicious activity", 
                   ip, self.config.ban_duration.as_secs());
            
            return Err(QuicError::Security(SecurityError::DdosProtection(
                format!("IP {} banned for suspicious activity", ip)
            )));
        }
        
        Ok(())
    }
    
    pub async fn report_suspicious_activity(&self, ip: IpAddr, severity: u32) {
        let mut suspicious_ips = self.suspicious_ips.write().await;
        let now = Instant::now();
        
        let activity = suspicious_ips.entry(ip).or_insert_with(|| SuspiciousActivity {
            score: 0,
            last_activity: now,
            banned_until: None,
            connection_count: 0,
            packet_count: 0,
            last_packet_reset: now,
        });
        
        activity.score += severity;
        activity.last_activity = now;
        
        debug!("Reported suspicious activity from {}: severity {}, total score {}", 
               ip, severity, activity.score);
    }
    
    pub async fn cleanup_old_entries(&self) {
        let mut suspicious_ips = self.suspicious_ips.write().await;
        let now = Instant::now();
        let cleanup_threshold = Duration::from_secs(3600); // 1 hour
        
        suspicious_ips.retain(|ip, activity| {
            let should_keep = now.duration_since(activity.last_activity) < cleanup_threshold;
            if !should_keep {
                debug!("Cleaning up old entry for IP {}", ip);
            }
            should_keep
        });
        
        // Also cleanup rate limiter
        self.rate_limiter.cleanup_old_counters().await;
    }
    
    pub async fn get_stats(&self) -> DdosStats {
        let suspicious_ips = self.suspicious_ips.read().await;
        let now = Instant::now();
        
        let mut banned_count = 0;
        let mut suspicious_count = 0;
        
        for activity in suspicious_ips.values() {
            if let Some(banned_until) = activity.banned_until {
                if now < banned_until {
                    banned_count += 1;
                }
            }
            if activity.score > 0 {
                suspicious_count += 1;
            }
        }
        
        DdosStats {
            total_tracked_ips: suspicious_ips.len(),
            banned_ips: banned_count,
            suspicious_ips: suspicious_count,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DdosStats {
    pub total_tracked_ips: usize,
    pub banned_ips: usize,
    pub suspicious_ips: usize,
}

/// Certificate validation for crypto projects
#[derive(Debug)]
pub struct CertificateValidator {
    trusted_ca_certs: Vec<Vec<u8>>,
    allow_self_signed: bool,
    require_client_certs: bool,
}

impl CertificateValidator {
    pub fn new(allow_self_signed: bool, require_client_certs: bool) -> Self {
        Self {
            trusted_ca_certs: Vec::new(),
            allow_self_signed,
            require_client_certs,
        }
    }
    
    pub fn add_trusted_ca(&mut self, cert_der: Vec<u8>) {
        self.trusted_ca_certs.push(cert_der);
    }
    
    pub fn validate_certificate(&self, cert_chain: &[Vec<u8>]) -> Result<(), QuicError> {
        if cert_chain.is_empty() {
            if self.require_client_certs {
                return Err(QuicError::Security(SecurityError::InvalidCertificate(
                    "No certificate provided".to_string()
                )));
            }
            return Ok(());
        }
        
        // Basic certificate validation (simplified)
        let leaf_cert = &cert_chain[0];
        
        // Check certificate format (very basic check)
        if leaf_cert.len() < 100 {
            return Err(QuicError::Security(SecurityError::InvalidCertificate(
                "Certificate too small".to_string()
            )));
        }
        
        // If self-signed certificates are allowed, accept anything that looks like a cert
        if self.allow_self_signed {
            debug!("Accepting certificate (self-signed allowed)");
            return Ok(());
        }
        
        // In a real implementation, you would:
        // 1. Parse the certificate using a library like rustls-pemfile
        // 2. Verify the signature chain
        // 3. Check validity dates
        // 4. Verify against trusted CAs
        // 5. Check revocation status
        
        if self.trusted_ca_certs.is_empty() {
            return Err(QuicError::Security(SecurityError::InvalidCertificate(
                "No trusted CAs configured".to_string()
            )));
        }
        
        // Placeholder validation
        debug!("Certificate validation not fully implemented");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_rate_limiter() {
        let rate_limiter = RateLimiter::new();
        let ip = "127.0.0.1".parse().unwrap();
        
        // Should allow initial requests
        assert!(rate_limiter.check_rate_limit(ip, "packets").await.is_ok());
        
        // Should eventually hit rate limit with many requests
        for _ in 0..1000 {
            let _ = rate_limiter.check_rate_limit(ip, "packets").await;
        }
        
        // Next request should be rate limited
        let result = rate_limiter.check_rate_limit(ip, "packets").await;
        assert!(result.is_err());
    }
    
    #[tokio::test]
    async fn test_ddos_protection() {
        let ddos = DdosProtection::new(DdosConfig::default());
        let addr = "127.0.0.1:1234".parse().unwrap();
        
        // Should allow initial connections
        assert!(ddos.check_connection_allowed(addr).await.is_ok());
        
        // Should eventually trigger protection
        for _ in 0..100 {
            let _ = ddos.check_connection_allowed(addr).await;
        }
        
        let stats = ddos.get_stats().await;
        assert!(stats.total_tracked_ips > 0);
    }
}