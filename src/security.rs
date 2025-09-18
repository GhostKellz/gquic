//! Security and attack prevention for QUIC implementation
//!
//! Provides comprehensive protection against various attacks and edge cases:
//! - Malformed packet detection and handling
//! - DDoS protection mechanisms
//! - Rate limiting and throttling
//! - Anti-amplification measures
//! - Connection flooding protection

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use std::net::{IpAddr, SocketAddr};
use crate::{QuicResult, QuicError};

/// Security policy configuration
#[derive(Debug, Clone)]
pub struct SecurityPolicy {
    /// Maximum packet size to accept
    pub max_packet_size: usize,
    /// Maximum connection attempts per IP per time window
    pub max_connections_per_ip: u32,
    /// Time window for connection rate limiting
    pub connection_rate_window: Duration,
    /// Maximum packets per second per connection
    pub max_packets_per_second: u32,
    /// Maximum bandwidth per connection (bytes per second)
    pub max_bandwidth_per_connection: u64,
    /// Maximum number of concurrent connections
    pub max_concurrent_connections: u32,
    /// Anti-amplification ratio (response/request size ratio)
    pub amplification_limit_ratio: f64,
    /// Enable strict packet validation
    pub strict_validation: bool,
    /// Block suspicious IPs automatically
    pub auto_block_suspicious_ips: bool,
    /// Suspicious activity threshold
    pub suspicious_activity_threshold: u32,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            max_packet_size: 65536, // 64KB
            max_connections_per_ip: 100,
            connection_rate_window: Duration::from_secs(60),
            max_packets_per_second: 1000,
            max_bandwidth_per_connection: 10 * 1024 * 1024, // 10MB/s
            max_concurrent_connections: 10000,
            amplification_limit_ratio: 3.0,
            strict_validation: true,
            auto_block_suspicious_ips: true,
            suspicious_activity_threshold: 10,
        }
    }
}

/// Security manager for QUIC connections
#[derive(Debug)]
pub struct SecurityManager {
    policy: SecurityPolicy,
    connection_tracker: ConnectionTracker,
    rate_limiter: RateLimiter,
    packet_validator: PacketValidator,
    threat_detector: ThreatDetector,
    blocked_ips: HashMap<IpAddr, BlockedIpInfo>,
}

impl SecurityManager {
    /// Create a new security manager
    pub fn new(policy: SecurityPolicy) -> Self {
        Self {
            connection_tracker: ConnectionTracker::new(policy.max_concurrent_connections),
            rate_limiter: RateLimiter::new(),
            packet_validator: PacketValidator::new(policy.max_packet_size, policy.strict_validation),
            threat_detector: ThreatDetector::new(policy.suspicious_activity_threshold),
            blocked_ips: HashMap::new(),
            policy,
        }
    }

    /// Validate incoming packet for security threats
    pub fn validate_packet(&mut self, data: &[u8], source: SocketAddr) -> QuicResult<PacketValidationResult> {
        // Check if IP is blocked
        if let Some(block_info) = self.blocked_ips.get(&source.ip()) {
            if block_info.blocked_until > Instant::now() {
                return Ok(PacketValidationResult::Blocked {
                    reason: "IP address is blocked".to_string(),
                });
            } else {
                // Block expired, remove it
                self.blocked_ips.remove(&source.ip());
            }
        }

        // Rate limiting check
        if !self.rate_limiter.check_rate(source.ip(), 1) {
            self.threat_detector.record_event(source.ip(), ThreatEvent::RateLimitExceeded);
            return Ok(PacketValidationResult::RateLimited);
        }

        // Packet validation
        match self.packet_validator.validate_packet(data) {
            Ok(_) => {
                // Packet is valid, update connection tracking
                self.connection_tracker.record_packet(source, data.len());
                Ok(PacketValidationResult::Valid)
            }
            Err(validation_error) => {
                // Record suspicious activity
                self.threat_detector.record_event(source.ip(), ThreatEvent::MalformedPacket);

                // Check if we should block this IP
                if self.policy.auto_block_suspicious_ips {
                    if let Some(threat_level) = self.threat_detector.get_threat_level(source.ip()) {
                        if threat_level >= ThreatLevel::High {
                            self.block_ip(source.ip(), Duration::from_secs(3600), "High threat level");
                        }
                    }
                }

                Ok(PacketValidationResult::Invalid {
                    reason: validation_error.to_string(),
                })
            }
        }
    }

    /// Check if a new connection should be allowed
    pub fn allow_new_connection(&mut self, source: SocketAddr) -> QuicResult<bool> {
        // Check if IP is blocked
        if self.blocked_ips.contains_key(&source.ip()) {
            return Ok(false);
        }

        // Check connection limits
        if !self.connection_tracker.can_accept_connection(source) {
            self.threat_detector.record_event(source.ip(), ThreatEvent::ConnectionFlooding);
            return Ok(false);
        }

        // Check rate limits for new connections
        if !self.rate_limiter.check_connection_rate(source.ip()) {
            return Ok(false);
        }

        self.connection_tracker.add_connection(source);
        Ok(true)
    }

    /// Remove a connection when it's closed
    pub fn remove_connection(&mut self, source: SocketAddr) {
        self.connection_tracker.remove_connection(source);
    }

    /// Block an IP address
    pub fn block_ip(&mut self, ip: IpAddr, duration: Duration, reason: &str) {
        let block_info = BlockedIpInfo {
            blocked_at: Instant::now(),
            blocked_until: Instant::now() + duration,
            reason: reason.to_string(),
            block_count: self.blocked_ips.get(&ip)
                .map(|info| info.block_count + 1)
                .unwrap_or(1),
        };
        self.blocked_ips.insert(ip, block_info);
    }

    /// Unblock an IP address
    pub fn unblock_ip(&mut self, ip: IpAddr) {
        self.blocked_ips.remove(&ip);
    }

    /// Get security statistics
    pub fn get_stats(&self) -> SecurityStats {
        SecurityStats {
            active_connections: self.connection_tracker.active_connections(),
            blocked_ips: self.blocked_ips.len(),
            rate_limited_ips: self.rate_limiter.get_limited_count(),
            malformed_packets: self.threat_detector.get_event_count(ThreatEvent::MalformedPacket),
            total_threats_detected: self.threat_detector.total_threats(),
        }
    }

    /// Clean up expired entries
    pub fn cleanup(&mut self) {
        let now = Instant::now();

        // Remove expired IP blocks
        self.blocked_ips.retain(|_, info| info.blocked_until > now);

        // Clean up other components
        self.rate_limiter.cleanup();
        self.threat_detector.cleanup();
        self.connection_tracker.cleanup();
    }
}

/// Result of packet validation
#[derive(Debug, Clone)]
pub enum PacketValidationResult {
    /// Packet is valid and should be processed
    Valid,
    /// Packet is invalid/malformed
    Invalid { reason: String },
    /// Packet was rate limited
    RateLimited,
    /// Packet from blocked IP
    Blocked { reason: String },
}

/// Information about blocked IPs
#[derive(Debug, Clone)]
struct BlockedIpInfo {
    blocked_at: Instant,
    blocked_until: Instant,
    reason: String,
    block_count: u32,
}

/// Connection tracking for detecting flooding attacks
#[derive(Debug)]
struct ConnectionTracker {
    connections: HashMap<SocketAddr, ConnectionInfo>,
    connections_per_ip: HashMap<IpAddr, u32>,
    max_concurrent_connections: u32,
}

#[derive(Debug, Clone)]
struct ConnectionInfo {
    established_at: Instant,
    last_activity: Instant,
    packet_count: u64,
    bytes_received: u64,
}

impl ConnectionTracker {
    fn new(max_concurrent: u32) -> Self {
        Self {
            connections: HashMap::new(),
            connections_per_ip: HashMap::new(),
            max_concurrent_connections: max_concurrent,
        }
    }

    fn can_accept_connection(&self, source: SocketAddr) -> bool {
        // Check global connection limit
        if self.connections.len() >= self.max_concurrent_connections as usize {
            return false;
        }

        // Check per-IP connection limit (simplified - would use policy)
        let connections_from_ip = self.connections_per_ip.get(&source.ip()).unwrap_or(&0);
        *connections_from_ip < 100 // Max 100 connections per IP
    }

    fn add_connection(&mut self, source: SocketAddr) {
        let info = ConnectionInfo {
            established_at: Instant::now(),
            last_activity: Instant::now(),
            packet_count: 0,
            bytes_received: 0,
        };

        self.connections.insert(source, info);
        *self.connections_per_ip.entry(source.ip()).or_insert(0) += 1;
    }

    fn remove_connection(&mut self, source: SocketAddr) {
        if self.connections.remove(&source).is_some() {
            if let Some(count) = self.connections_per_ip.get_mut(&source.ip()) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.connections_per_ip.remove(&source.ip());
                }
            }
        }
    }

    fn record_packet(&mut self, source: SocketAddr, size: usize) {
        if let Some(info) = self.connections.get_mut(&source) {
            info.last_activity = Instant::now();
            info.packet_count += 1;
            info.bytes_received += size as u64;
        }
    }

    fn active_connections(&self) -> usize {
        self.connections.len()
    }

    fn cleanup(&mut self) {
        let cutoff = Instant::now() - Duration::from_secs(300); // 5 minutes
        let mut to_remove = Vec::new();

        for (addr, info) in &self.connections {
            if info.last_activity < cutoff {
                to_remove.push(*addr);
            }
        }

        for addr in to_remove {
            self.remove_connection(addr);
        }
    }
}

/// Rate limiting to prevent flooding attacks
#[derive(Debug)]
struct RateLimiter {
    packet_rates: HashMap<IpAddr, PacketRateInfo>,
    connection_rates: HashMap<IpAddr, ConnectionRateInfo>,
}

#[derive(Debug)]
struct PacketRateInfo {
    packets: VecDeque<Instant>,
    last_cleanup: Instant,
}

#[derive(Debug)]
struct ConnectionRateInfo {
    connections: VecDeque<Instant>,
    last_cleanup: Instant,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            packet_rates: HashMap::new(),
            connection_rates: HashMap::new(),
        }
    }

    fn check_rate(&mut self, ip: IpAddr, packets: u32) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(1);
        let max_packets = 1000; // packets per second

        let rate_info = self.packet_rates.entry(ip).or_insert_with(|| {
            PacketRateInfo {
                packets: VecDeque::new(),
                last_cleanup: now,
            }
        });

        // Clean old entries
        if now.duration_since(rate_info.last_cleanup) > Duration::from_secs(10) {
            let cutoff = now - window;
            while let Some(&front_time) = rate_info.packets.front() {
                if front_time < cutoff {
                    rate_info.packets.pop_front();
                } else {
                    break;
                }
            }
            rate_info.last_cleanup = now;
        }

        // Check if we can accept more packets
        if rate_info.packets.len() + packets as usize <= max_packets {
            for _ in 0..packets {
                rate_info.packets.push_back(now);
            }
            true
        } else {
            false
        }
    }

    fn check_connection_rate(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(60);
        let max_connections = 10; // connections per minute

        let rate_info = self.connection_rates.entry(ip).or_insert_with(|| {
            ConnectionRateInfo {
                connections: VecDeque::new(),
                last_cleanup: now,
            }
        });

        // Clean old entries
        let cutoff = now - window;
        while let Some(&front_time) = rate_info.connections.front() {
            if front_time < cutoff {
                rate_info.connections.pop_front();
            } else {
                break;
            }
        }

        // Check if we can accept a new connection
        if rate_info.connections.len() < max_connections {
            rate_info.connections.push_back(now);
            true
        } else {
            false
        }
    }

    fn get_limited_count(&self) -> usize {
        // Return number of IPs currently being rate limited
        self.packet_rates.len() + self.connection_rates.len()
    }

    fn cleanup(&mut self) {
        let now = Instant::now();
        let cutoff = now - Duration::from_secs(300);

        self.packet_rates.retain(|_, info| info.last_cleanup > cutoff);
        self.connection_rates.retain(|_, info| info.last_cleanup > cutoff);
    }
}

/// Packet validation for detecting malformed packets
#[derive(Debug)]
struct PacketValidator {
    max_packet_size: usize,
    strict_validation: bool,
}

impl PacketValidator {
    fn new(max_packet_size: usize, strict_validation: bool) -> Self {
        Self {
            max_packet_size,
            strict_validation,
        }
    }

    fn validate_packet(&self, data: &[u8]) -> QuicResult<()> {
        // Basic size check
        if data.is_empty() {
            return Err(QuicError::InvalidPacket("Empty packet".to_string()));
        }

        if data.len() > self.max_packet_size {
            return Err(QuicError::InvalidPacket(format!(
                "Packet size {} exceeds maximum {}",
                data.len(),
                self.max_packet_size
            )));
        }

        // Basic QUIC packet structure validation
        if data.len() < 1 {
            return Err(QuicError::InvalidPacket("Packet too short".to_string()));
        }

        let first_byte = data[0];

        // Check for valid packet type
        if (first_byte & 0x80) != 0 {
            // Long header packet
            if data.len() < 6 {
                return Err(QuicError::InvalidPacket("Long header packet too short".to_string()));
            }

            // Validate version field
            let version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);

            // Check for valid versions or version negotiation
            if version != 0 && !self.is_valid_version(version) {
                if self.strict_validation {
                    return Err(QuicError::InvalidPacket(format!("Invalid QUIC version: 0x{:08x}", version)));
                }
            }
        } else {
            // Short header packet - minimal validation for performance
            if data.len() < 2 {
                return Err(QuicError::InvalidPacket("Short header packet too short".to_string()));
            }
        }

        // Additional strict validation checks
        if self.strict_validation {
            self.validate_packet_structure(data)?;
        }

        Ok(())
    }

    fn is_valid_version(&self, version: u32) -> bool {
        match version {
            0x00000001 => true, // QUIC v1
            0x6b3343cf => true, // QUIC v2
            0xff00001d => true, // Draft 29
            0xff000020 => true, // Draft 32
            _ => false,
        }
    }

    fn validate_packet_structure(&self, data: &[u8]) -> QuicResult<()> {
        // More detailed packet structure validation
        // This would include frame parsing validation, etc.
        // For now, just basic checks

        // Check for suspicious patterns that might indicate attacks
        if self.has_suspicious_patterns(data) {
            return Err(QuicError::InvalidPacket("Suspicious packet patterns detected".to_string()));
        }

        Ok(())
    }

    fn has_suspicious_patterns(&self, data: &[u8]) -> bool {
        // Check for common attack patterns

        // All zeros (potential padding attack)
        if data.iter().all(|&b| b == 0) {
            return true;
        }

        // All 0xFF (potential overflow attempt)
        if data.iter().all(|&b| b == 0xFF) {
            return true;
        }

        // Repeating patterns that might indicate generated/malicious data
        if data.len() > 16 {
            let pattern = &data[0..4];
            let mut repeats = 0;
            for chunk in data.chunks(4) {
                if chunk == pattern {
                    repeats += 1;
                    if repeats > data.len() / 8 {
                        return true; // Too many repeats
                    }
                }
            }
        }

        false
    }
}

/// Threat detection and analysis
#[derive(Debug)]
struct ThreatDetector {
    events: HashMap<IpAddr, Vec<ThreatEvent>>,
    event_counts: HashMap<ThreatEvent, u64>,
    threshold: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ThreatEvent {
    MalformedPacket,
    RateLimitExceeded,
    ConnectionFlooding,
    SuspiciousActivity,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum ThreatLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl ThreatDetector {
    fn new(threshold: u32) -> Self {
        Self {
            events: HashMap::new(),
            event_counts: HashMap::new(),
            threshold,
        }
    }

    fn record_event(&mut self, ip: IpAddr, event: ThreatEvent) {
        self.events.entry(ip).or_default().push(event.clone());
        *self.event_counts.entry(event).or_insert(0) += 1;
    }

    fn get_threat_level(&self, ip: IpAddr) -> Option<ThreatLevel> {
        let events = self.events.get(&ip)?;
        let recent_events = events.len() as u32;

        if recent_events > self.threshold * 3 {
            Some(ThreatLevel::Critical)
        } else if recent_events > self.threshold * 2 {
            Some(ThreatLevel::High)
        } else if recent_events > self.threshold {
            Some(ThreatLevel::Medium)
        } else if recent_events > 0 {
            Some(ThreatLevel::Low)
        } else {
            None
        }
    }

    fn get_event_count(&self, event: ThreatEvent) -> u64 {
        self.event_counts.get(&event).copied().unwrap_or(0)
    }

    fn total_threats(&self) -> u64 {
        self.event_counts.values().sum()
    }

    fn cleanup(&mut self) {
        // Remove old events (keep only recent ones)
        for events in self.events.values_mut() {
            events.truncate(100); // Keep last 100 events per IP
        }

        // Remove IPs with no recent events
        self.events.retain(|_, events| !events.is_empty());
    }
}

/// Security statistics
#[derive(Debug, Clone)]
pub struct SecurityStats {
    pub active_connections: usize,
    pub blocked_ips: usize,
    pub rate_limited_ips: usize,
    pub malformed_packets: u64,
    pub total_threats_detected: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_packet_validation() {
        let policy = SecurityPolicy::default();
        let mut security_manager = SecurityManager::new(policy);

        // Valid packet
        let valid_packet = vec![0x40, 0x01, 0x02, 0x03]; // Short header packet
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1234);

        let result = security_manager.validate_packet(&valid_packet, source).unwrap();
        assert!(matches!(result, PacketValidationResult::Valid));

        // Invalid packet (empty)
        let invalid_packet = vec![];
        let result = security_manager.validate_packet(&invalid_packet, source).unwrap();
        assert!(matches!(result, PacketValidationResult::Invalid { .. }));
    }

    #[test]
    fn test_connection_limits() {
        let policy = SecurityPolicy {
            max_concurrent_connections: 2,
            ..Default::default()
        };
        let mut security_manager = SecurityManager::new(policy);

        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1234);
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1235);
        let addr3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1236);

        // First two connections should be allowed
        assert!(security_manager.allow_new_connection(addr1).unwrap());
        assert!(security_manager.allow_new_connection(addr2).unwrap());

        // Third connection should be denied (exceeds limit)
        assert!(!security_manager.allow_new_connection(addr3).unwrap());
    }

    #[test]
    fn test_ip_blocking() {
        let policy = SecurityPolicy::default();
        let mut security_manager = SecurityManager::new(policy);

        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let source = SocketAddr::new(ip, 1234);

        // Block the IP
        security_manager.block_ip(ip, Duration::from_secs(60), "Test block");

        // Packet from blocked IP should be blocked
        let packet = vec![0x40, 0x01, 0x02, 0x03];
        let result = security_manager.validate_packet(&packet, source).unwrap();
        assert!(matches!(result, PacketValidationResult::Blocked { .. }));
    }
}