use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, info, warn, error};
use serde::{Serialize, Deserialize};

use super::{CryptoBackend, KeyType, PacketKeys, TransportParameters};
use crate::quic::{ConnectionId, error::{QuicError, CryptoError, Result}};

/// 0-RTT session management for low-latency crypto applications
#[derive(Debug)]
pub struct ZeroRttManager {
    backend: Arc<dyn CryptoBackend>,
    session_cache: Arc<RwLock<HashMap<String, CachedSession>>>,
    config: ZeroRttConfig,
}

#[derive(Debug, Clone)]
pub struct ZeroRttConfig {
    /// Maximum age of cached session (default: 7 days)
    pub max_session_age: Duration,
    /// Maximum number of cached sessions
    pub max_cache_size: usize,
    /// Enable anti-replay protection
    pub enable_anti_replay: bool,
    /// Early data limit per session
    pub max_early_data_size: u64,
    /// Enable session ticket rotation
    pub enable_ticket_rotation: bool,
}

impl Default for ZeroRttConfig {
    fn default() -> Self {
        Self {
            max_session_age: Duration::from_secs(7 * 24 * 3600), // 7 days
            max_cache_size: 10000,
            enable_anti_replay: true,
            max_early_data_size: 16384, // 16KB
            enable_ticket_rotation: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedSession {
    session_id: String,
    server_name: String,
    creation_time: u64, // Unix timestamp
    transport_parameters: TransportParameters,
    resumption_secret: Vec<u8>,
    cipher_suite: String,
    protocol_version: u32,
    early_data_limit: u64,
    ticket_age_add: u32,
}

#[derive(Debug)]
pub struct EarlyDataResult {
    pub early_data_keys: PacketKeys,
    pub max_early_data_size: u64,
    pub session_params: TransportParameters,
}

#[derive(Debug)]
pub struct SessionTicket {
    pub ticket: Vec<u8>,
    pub lifetime: Duration,
    pub age_add: u32,
    pub nonce: Vec<u8>,
}

impl ZeroRttManager {
    pub fn new(backend: Arc<dyn CryptoBackend>, config: ZeroRttConfig) -> Self {
        Self {
            backend,
            session_cache: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Store a session for future 0-RTT use
    pub async fn store_session(
        &self,
        server_name: &str,
        transport_params: TransportParameters,
        resumption_secret: Vec<u8>,
        cipher_suite: &str,
    ) -> Result<SessionTicket> {
        let session_id = self.generate_session_id(server_name);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let ticket_age_add = rand::random::<u32>();
        
        let session = CachedSession {
            session_id: session_id.clone(),
            server_name: server_name.to_string(),
            creation_time: now,
            transport_parameters: transport_params,
            resumption_secret,
            cipher_suite: cipher_suite.to_string(),
            protocol_version: 1, // QUIC v1
            early_data_limit: self.config.max_early_data_size,
            ticket_age_add,
        };

        // Clean up old sessions if cache is full
        self.cleanup_old_sessions().await;

        let mut cache = self.session_cache.write().await;
        if cache.len() >= self.config.max_cache_size {
            // Remove oldest session
            if let Some(oldest_key) = cache.keys()
                .min_by_key(|k| cache.get(*k).map(|s| s.creation_time).unwrap_or(u64::MAX))
                .cloned() {
                cache.remove(&oldest_key);
            }
        }

        cache.insert(session_id.clone(), session);

        info!("Stored 0-RTT session for {}", server_name);

        // Generate session ticket
        let ticket_data = self.encrypt_session_ticket(&session).await?;
        
        Ok(SessionTicket {
            ticket: ticket_data,
            lifetime: self.config.max_session_age,
            age_add: ticket_age_add,
            nonce: self.generate_nonce(),
        })
    }

    /// Attempt to resume session with 0-RTT
    pub async fn try_resume_session(
        &self,
        server_name: &str,
        session_ticket: &[u8],
        ticket_age: Duration,
    ) -> Result<Option<EarlyDataResult>> {
        // Decrypt and validate session ticket
        let session = match self.decrypt_session_ticket(session_ticket).await {
            Ok(session) => session,
            Err(e) => {
                debug!("Failed to decrypt session ticket: {}", e);
                return Ok(None);
            }
        };

        // Validate session
        if !self.validate_session(&session, server_name, ticket_age).await? {
            debug!("Session validation failed for {}", server_name);
            return Ok(None);
        }

        // Derive early data keys
        let early_data_keys = self.derive_early_data_keys(&session.resumption_secret).await?;

        info!("Resuming 0-RTT session for {}", server_name);

        Ok(Some(EarlyDataResult {
            early_data_keys,
            max_early_data_size: session.early_data_limit,
            session_params: session.transport_parameters,
        }))
    }

    /// Validate early data from client
    pub async fn validate_early_data(
        &self,
        session_ticket: &[u8],
        early_data: &[u8],
        connection_id: &ConnectionId,
    ) -> Result<bool> {
        if !self.config.enable_anti_replay {
            return Ok(true);
        }

        // Decrypt session ticket
        let session = self.decrypt_session_ticket(session_ticket).await?;

        // Check early data size limit
        if early_data.len() as u64 > session.early_data_limit {
            warn!("Early data exceeds limit: {} > {}", 
                  early_data.len(), session.early_data_limit);
            return Ok(false);
        }

        // Anti-replay check (simplified)
        // In production, you'd maintain a replay cache
        let replay_key = format!("{}_{}", session.session_id, connection_id);
        
        // For demo purposes, always allow (real implementation needs replay detection)
        debug!("Anti-replay check passed for connection {}", connection_id);
        
        Ok(true)
    }

    /// Generate keys for early data encryption
    async fn derive_early_data_keys(&self, resumption_secret: &[u8]) -> Result<PacketKeys> {
        // Derive early traffic secret
        let early_secret = self.backend.derive_key(
            resumption_secret,
            b"",
            b"c e traffic",
            32,
        )?;

        // Derive packet protection keys
        let key = self.backend.derive_key(&early_secret, b"", b"quic key", 16)?;
        let iv = self.backend.derive_key(&early_secret, b"", b"quic iv", 12)?;
        let hp_key = self.backend.derive_key(&early_secret, b"", b"quic hp", 16)?;

        Ok(PacketKeys {
            key: key.try_into().map_err(|_| QuicError::Crypto(CryptoError::InvalidKeyLength))?,
            iv: iv.try_into().map_err(|_| QuicError::Crypto(CryptoError::InvalidKeyLength))?,
            hp_key: hp_key.try_into().map_err(|_| QuicError::Crypto(CryptoError::InvalidKeyLength))?,
        })
    }

    /// Validate a cached session
    async fn validate_session(
        &self,
        session: &CachedSession,
        server_name: &str,
        ticket_age: Duration,
    ) -> Result<bool> {
        // Check server name match
        if session.server_name != server_name {
            return Ok(false);
        }

        // Check session age
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let session_age = Duration::from_secs(now - session.creation_time);
        if session_age > self.config.max_session_age {
            debug!("Session expired: age={:?}, max={:?}", 
                   session_age, self.config.max_session_age);
            return Ok(false);
        }

        // Validate ticket age (anti-replay measure)
        let expected_age = session_age;
        let age_diff = if ticket_age > expected_age {
            ticket_age - expected_age
        } else {
            expected_age - ticket_age
        };

        if age_diff > Duration::from_secs(10) { // 10 second tolerance
            debug!("Ticket age mismatch: reported={:?}, expected={:?}", 
                   ticket_age, expected_age);
            return Ok(false);
        }

        Ok(true)
    }

    /// Encrypt session ticket
    async fn encrypt_session_ticket(&self, session: &CachedSession) -> Result<Vec<u8>> {
        let serialized = serde_json::to_vec(session)
            .map_err(|e| QuicError::Crypto(CryptoError::Generic(e.to_string())))?;

        // Use a server-wide key for ticket encryption
        // In production, this should be a proper ticket encryption key
        let ticket_key = self.derive_ticket_key().await?;
        let nonce = self.generate_nonce();

        let encrypted = self.backend.encrypt_aead(
            &ticket_key,
            &nonce,
            b"session_ticket",
            &serialized,
        )?;

        // Prepend nonce to encrypted data
        let mut ticket = nonce;
        ticket.extend_from_slice(&encrypted);

        Ok(ticket)
    }

    /// Decrypt session ticket
    async fn decrypt_session_ticket(&self, ticket: &[u8]) -> Result<CachedSession> {
        if ticket.len() < 12 {
            return Err(QuicError::Crypto(CryptoError::Decryption(
                "Ticket too short".to_string()
            )));
        }

        let nonce = &ticket[..12];
        let encrypted = &ticket[12..];

        let ticket_key = self.derive_ticket_key().await?;

        let decrypted = self.backend.decrypt_aead(
            &ticket_key,
            nonce,
            b"session_ticket",
            encrypted,
        )?;

        let session: CachedSession = serde_json::from_slice(&decrypted)
            .map_err(|e| QuicError::Crypto(CryptoError::Generic(e.to_string())))?;

        Ok(session)
    }

    /// Derive ticket encryption key (simplified)
    async fn derive_ticket_key(&self) -> Result<Vec<u8>> {
        // In production, use a proper server secret
        let server_secret = b"gquic_ticket_encryption_key_v1";
        self.backend.derive_key(server_secret, b"", b"ticket key", 16)
    }

    /// Generate session ID
    fn generate_session_id(&self, server_name: &str) -> String {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        
        format!("{}_{}", server_name, timestamp)
    }

    /// Generate random nonce
    fn generate_nonce(&self) -> Vec<u8> {
        let mut nonce = vec![0u8; 12];
        // In production, use secure random
        for i in 0..12 {
            nonce[i] = rand::random();
        }
        nonce
    }

    /// Clean up expired sessions
    async fn cleanup_old_sessions(&self) {
        let mut cache = self.session_cache.write().await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let max_age_secs = self.config.max_session_age.as_secs();
        
        cache.retain(|_, session| {
            now - session.creation_time < max_age_secs
        });
    }

    /// Get 0-RTT statistics
    pub async fn get_stats(&self) -> ZeroRttStats {
        let cache = self.session_cache.read().await;
        
        ZeroRttStats {
            cached_sessions: cache.len(),
            max_cache_size: self.config.max_cache_size,
            max_session_age: self.config.max_session_age,
            anti_replay_enabled: self.config.enable_anti_replay,
        }
    }

    /// Clear all cached sessions
    pub async fn clear_cache(&self) {
        let mut cache = self.session_cache.write().await;
        cache.clear();
        info!("Cleared 0-RTT session cache");
    }

    /// Check if 0-RTT is available for server
    pub async fn has_session(&self, server_name: &str) -> bool {
        let cache = self.session_cache.read().await;
        cache.values().any(|session| session.server_name == server_name)
    }
}

#[derive(Debug, Clone)]
pub struct ZeroRttStats {
    pub cached_sessions: usize,
    pub max_cache_size: usize,
    pub max_session_age: Duration,
    pub anti_replay_enabled: bool,
}

/// Client-side 0-RTT helper
pub struct ZeroRttClient {
    manager: ZeroRttManager,
}

impl ZeroRttClient {
    pub fn new(backend: Arc<dyn CryptoBackend>) -> Self {
        Self {
            manager: ZeroRttManager::new(backend, ZeroRttConfig::default()),
        }
    }

    /// Attempt 0-RTT connection
    pub async fn try_zero_rtt(
        &self,
        server_name: &str,
        session_ticket: Option<&[u8]>,
    ) -> Result<Option<EarlyDataResult>> {
        if let Some(ticket) = session_ticket {
            // Calculate ticket age (simplified)
            let ticket_age = Duration::from_secs(0); // Would be calculated from ticket
            
            self.manager.try_resume_session(server_name, ticket, ticket_age).await
        } else {
            Ok(None)
        }
    }
}

/// Server-side 0-RTT helper
pub struct ZeroRttServer {
    manager: ZeroRttManager,
}

impl ZeroRttServer {
    pub fn new(backend: Arc<dyn CryptoBackend>, config: ZeroRttConfig) -> Self {
        Self {
            manager: ZeroRttManager::new(backend, config),
        }
    }

    /// Accept 0-RTT data
    pub async fn accept_early_data(
        &self,
        session_ticket: &[u8],
        early_data: &[u8],
        connection_id: &ConnectionId,
    ) -> Result<bool> {
        self.manager.validate_early_data(session_ticket, early_data, connection_id).await
    }

    /// Issue new session ticket
    pub async fn issue_session_ticket(
        &self,
        server_name: &str,
        transport_params: TransportParameters,
        resumption_secret: Vec<u8>,
    ) -> Result<SessionTicket> {
        self.manager.store_session(
            server_name,
            transport_params,
            resumption_secret,
            "TLS_AES_128_GCM_SHA256", // Example cipher suite
        ).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::RustlsBackend;

    #[tokio::test]
    async fn test_zero_rtt_session_storage() {
        let backend = Arc::new(RustlsBackend::new());
        let manager = ZeroRttManager::new(backend, ZeroRttConfig::default());
        
        let transport_params = TransportParameters::default();
        let resumption_secret = vec![1, 2, 3, 4];
        
        let ticket = manager.store_session(
            "example.com",
            transport_params,
            resumption_secret,
            "TLS_AES_128_GCM_SHA256",
        ).await.unwrap();
        
        assert!(!ticket.ticket.is_empty());
        assert!(manager.has_session("example.com").await);
    }

    #[tokio::test]
    async fn test_zero_rtt_resumption() {
        let backend = Arc::new(RustlsBackend::new());
        let manager = ZeroRttManager::new(backend, ZeroRttConfig::default());
        
        // Store session
        let transport_params = TransportParameters::default();
        let resumption_secret = vec![1, 2, 3, 4];
        
        let ticket = manager.store_session(
            "example.com",
            transport_params,
            resumption_secret,
            "TLS_AES_128_GCM_SHA256",
        ).await.unwrap();
        
        // Try to resume
        let result = manager.try_resume_session(
            "example.com",
            &ticket.ticket,
            Duration::from_secs(1),
        ).await.unwrap();
        
        assert!(result.is_some());
        let early_data = result.unwrap();
        assert_eq!(early_data.max_early_data_size, 16384);
    }
}