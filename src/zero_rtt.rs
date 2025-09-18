//! 0-RTT Connection Resumption Implementation
//!
//! Provides early data transmission capability for resumed connections,
//! enabling clients to send data immediately without waiting for handshake.

use crate::{QuicError, QuicResult, Connection, ConnectionId};
use crate::crypto::{CryptoBackend, PublicKey, PrivateKey};
use bytes::{Bytes, BytesMut, BufMut};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 0-RTT session ticket for connection resumption
#[derive(Debug, Clone)]
pub struct SessionTicket {
    /// Ticket identifier
    pub ticket_id: Vec<u8>,
    /// Session resumption secret
    pub resumption_secret: Vec<u8>,
    /// Server configuration
    pub server_config: ServerConfig,
    /// Ticket creation time
    pub created_at: SystemTime,
    /// Ticket lifetime
    pub lifetime: Duration,
    /// Maximum early data size
    pub max_early_data: u32,
    /// ALPN protocol
    pub alpn_protocol: Option<String>,
}

/// Server configuration for 0-RTT
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Server certificate chain
    pub cert_chain: Vec<Vec<u8>>,
    /// Supported cipher suites
    pub cipher_suites: Vec<CipherSuite>,
    /// Maximum idle timeout
    pub max_idle_timeout: Duration,
    /// Initial maximum data
    pub initial_max_data: u64,
    /// Initial maximum stream data
    pub initial_max_stream_data: u64,
}

/// Cipher suite for 0-RTT
#[derive(Debug, Clone, PartialEq)]
pub enum CipherSuite {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

/// 0-RTT handler for managing early data
pub struct ZeroRttHandler {
    /// Session ticket store
    ticket_store: Arc<RwLock<HashMap<Vec<u8>, SessionTicket>>>,
    /// Early data buffer
    early_data: Arc<Mutex<HashMap<ConnectionId, Vec<u8>>>>,
    /// Anti-replay cache
    replay_cache: Arc<Mutex<ReplayCache>>,
    /// Configuration
    config: ZeroRttConfig,
}

/// 0-RTT configuration
#[derive(Debug, Clone)]
pub struct ZeroRttConfig {
    /// Enable 0-RTT
    pub enabled: bool,
    /// Maximum early data size per connection
    pub max_early_data_size: u32,
    /// Session ticket lifetime
    pub ticket_lifetime: Duration,
    /// Maximum number of tickets to issue
    pub max_tickets: usize,
    /// Enable anti-replay protection
    pub anti_replay: bool,
}

impl Default for ZeroRttConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_early_data_size: 16384,
            ticket_lifetime: Duration::from_secs(7 * 24 * 3600), // 7 days
            max_tickets: 2,
            anti_replay: true,
        }
    }
}

/// Anti-replay cache for 0-RTT
pub struct ReplayCache {
    /// Seen ClientHello hashes
    seen: HashMap<Vec<u8>, SystemTime>,
    /// Cache expiry duration
    expiry: Duration,
}

impl ReplayCache {
    /// Create a new replay cache
    pub fn new(expiry: Duration) -> Self {
        Self {
            seen: HashMap::new(),
            expiry,
        }
    }

    /// Check if ClientHello has been seen (potential replay)
    pub fn check_and_insert(&mut self, client_hello_hash: Vec<u8>) -> bool {
        // Clean expired entries
        let now = SystemTime::now();
        self.seen.retain(|_, time| {
            now.duration_since(*time).unwrap_or(Duration::MAX) < self.expiry
        });

        // Check if already seen
        if self.seen.contains_key(&client_hello_hash) {
            return true; // Replay detected
        }

        // Insert new hash
        self.seen.insert(client_hello_hash, now);
        false
    }
}

impl ZeroRttHandler {
    /// Create a new 0-RTT handler
    pub fn new(config: ZeroRttConfig) -> Self {
        Self {
            ticket_store: Arc::new(RwLock::new(HashMap::new())),
            early_data: Arc::new(Mutex::new(HashMap::new())),
            replay_cache: Arc::new(Mutex::new(ReplayCache::new(Duration::from_secs(60)))),
            config,
        }
    }

    /// Issue a new session ticket
    pub async fn issue_ticket(
        &self,
        conn: &Connection,
    ) -> QuicResult<SessionTicket> {
        if !self.config.enabled {
            return Err(QuicError::Protocol("0-RTT not enabled".into()));
        }

        // Generate ticket ID
        let ticket_id = generate_ticket_id();

        // Derive resumption secret
        let resumption_secret = vec![0u8; 32]; // Placeholder

        // Create server config
        let server_config = ServerConfig {
            cert_chain: vec![],
            cipher_suites: vec![CipherSuite::Aes256Gcm],
            max_idle_timeout: Duration::from_secs(30),
            initial_max_data: 10_000_000,
            initial_max_stream_data: 1_000_000,
        };

        // Create ticket
        let ticket = SessionTicket {
            ticket_id: ticket_id.clone(),
            resumption_secret,
            server_config,
            created_at: SystemTime::now(),
            lifetime: self.config.ticket_lifetime,
            max_early_data: self.config.max_early_data_size,
            alpn_protocol: None,
        };

        // Store ticket
        let mut store = self.ticket_store.write().await;
        store.insert(ticket_id, ticket.clone());

        // Clean old tickets
        if store.len() > self.config.max_tickets * 10 {
            self.clean_expired_tickets(&mut store).await;
        }

        Ok(ticket)
    }

    /// Validate and accept a session ticket
    pub async fn validate_ticket(
        &self,
        ticket_id: &[u8],
        client_hello_hash: &[u8],
    ) -> QuicResult<SessionTicket> {
        if !self.config.enabled {
            return Err(QuicError::Protocol("0-RTT not enabled".into()));
        }

        // Anti-replay check
        if self.config.anti_replay {
            let mut cache = self.replay_cache.lock().await;
            if cache.check_and_insert(client_hello_hash.to_vec()) {
                return Err(QuicError::Protocol("Replay attack detected".into()));
            }
        }

        // Lookup ticket
        let store = self.ticket_store.read().await;
        let ticket = store.get(ticket_id)
            .ok_or_else(|| QuicError::Protocol("Invalid ticket".into()))?;

        // Check expiry
        let age = SystemTime::now()
            .duration_since(ticket.created_at)
            .map_err(|_| QuicError::Protocol("Invalid ticket time".into()))?;

        if age > ticket.lifetime {
            return Err(QuicError::Protocol("Ticket expired".into()));
        }

        Ok(ticket.clone())
    }

    /// Process early data
    pub async fn process_early_data(
        &self,
        conn_id: ConnectionId,
        data: &[u8],
        ticket: &SessionTicket,
    ) -> QuicResult<()> {
        if data.len() > ticket.max_early_data as usize {
            return Err(QuicError::Protocol("Early data too large".into()));
        }

        // Decrypt early data using resumption secret
        let decrypted = decrypt_early_data(data, &ticket.resumption_secret)?;

        // Store for later processing
        let mut early_data = self.early_data.lock().await;
        early_data.insert(conn_id, decrypted);

        Ok(())
    }

    /// Retrieve processed early data
    pub async fn get_early_data(&self, conn_id: &ConnectionId) -> Option<Vec<u8>> {
        let mut early_data = self.early_data.lock().await;
        early_data.remove(conn_id)
    }

    /// Clean expired tickets
    async fn clean_expired_tickets(&self, store: &mut HashMap<Vec<u8>, SessionTicket>) {
        let now = SystemTime::now();
        store.retain(|_, ticket| {
            now.duration_since(ticket.created_at)
                .map(|age| age < ticket.lifetime)
                .unwrap_or(false)
        });
    }
}

/// Client-side 0-RTT support
pub struct ZeroRttClient {
    /// Stored session tickets
    tickets: Arc<RwLock<HashMap<String, Vec<SessionTicket>>>>,
    /// Configuration
    config: ZeroRttConfig,
}

impl ZeroRttClient {
    /// Create a new 0-RTT client
    pub fn new(config: ZeroRttConfig) -> Self {
        Self {
            tickets: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Store a session ticket
    pub async fn store_ticket(&self, server: String, ticket: SessionTicket) {
        let mut tickets = self.tickets.write().await;
        let server_tickets = tickets.entry(server).or_insert_with(Vec::new);

        // Keep only recent tickets
        server_tickets.retain(|t| {
            SystemTime::now()
                .duration_since(t.created_at)
                .map(|age| age < t.lifetime)
                .unwrap_or(false)
        });

        server_tickets.push(ticket);

        // Limit number of tickets per server
        if server_tickets.len() > self.config.max_tickets {
            server_tickets.drain(0..server_tickets.len() - self.config.max_tickets);
        }
    }

    /// Get a valid ticket for a server
    pub async fn get_ticket(&self, server: &str) -> Option<SessionTicket> {
        let tickets = self.tickets.read().await;
        tickets.get(server)?.iter()
            .filter(|t| {
                SystemTime::now()
                    .duration_since(t.created_at)
                    .map(|age| age < t.lifetime)
                    .unwrap_or(false)
            })
            .last()
            .cloned()
    }

    /// Send early data with 0-RTT
    pub async fn send_early_data(
        &self,
        conn: &mut Connection,
        ticket: &SessionTicket,
        data: &[u8],
    ) -> QuicResult<()> {
        if data.len() > ticket.max_early_data as usize {
            return Err(QuicError::Protocol("Early data too large".into()));
        }

        // Encrypt early data
        let encrypted = encrypt_early_data(data, &ticket.resumption_secret)?;

        // Send in 0-RTT packet
        conn.send_zero_rtt(&encrypted).await?;

        Ok(())
    }
}

/// Generate a random ticket ID
fn generate_ticket_id() -> Vec<u8> {
    let mut id = vec![0u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut id)
        .expect("Failed to generate random ticket ID");
    id
}

/// Encrypt early data
fn encrypt_early_data(data: &[u8], secret: &[u8]) -> QuicResult<Vec<u8>> {
    // Derive early data key
    let key = derive_early_data_key(secret)?;

    // Create AEAD
    let unbound_key = UnboundKey::new(&aead::AES_256_GCM, &key)
        .map_err(|_| QuicError::Crypto("Failed to create key".into()))?;
    let key = LessSafeKey::new(unbound_key);

    // Generate nonce
    let mut nonce_bytes = [0u8; 12];
    ring::rand::SystemRandom::new()
        .fill(&mut nonce_bytes)
        .map_err(|_| QuicError::Crypto("Failed to generate nonce".into()))?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    // Encrypt
    let mut encrypted = data.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut encrypted)
        .map_err(|_| QuicError::Crypto("Encryption failed".into()))?;

    // Prepend nonce
    let mut result = nonce_bytes.to_vec();
    result.extend(encrypted);

    Ok(result)
}

/// Decrypt early data
fn decrypt_early_data(data: &[u8], secret: &[u8]) -> QuicResult<Vec<u8>> {
    if data.len() < 12 {
        return Err(QuicError::Crypto("Invalid encrypted data".into()));
    }

    // Extract nonce
    let nonce_bytes: [u8; 12] = data[..12].try_into()
        .map_err(|_| QuicError::Crypto("Invalid nonce".into()))?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    // Derive early data key
    let key = derive_early_data_key(secret)?;

    // Create AEAD
    let unbound_key = UnboundKey::new(&aead::AES_256_GCM, &key)
        .map_err(|_| QuicError::Crypto("Failed to create key".into()))?;
    let key = LessSafeKey::new(unbound_key);

    // Decrypt
    let mut decrypted = data[12..].to_vec();
    key.open_in_place(nonce, Aad::empty(), &mut decrypted)
        .map_err(|_| QuicError::Crypto("Decryption failed".into()))?;

    // Remove tag
    let data_len = decrypted.len() - aead::AES_256_GCM.tag_len();
    decrypted.truncate(data_len);

    Ok(decrypted)
}

/// Derive early data key from secret
fn derive_early_data_key(secret: &[u8]) -> QuicResult<Vec<u8>> {
    use ring::hkdf;

    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, b"quic 0-rtt");
    let prk = salt.extract(secret);

    let info = [b"early data key"];
    let okm = prk.expand(&info, hkdf::HKDF_SHA256)
        .map_err(|_| QuicError::Crypto("HKDF expand failed".into()))?;

    let mut key = vec![0u8; 32];
    okm.fill(&mut key)
        .map_err(|_| QuicError::Crypto("Key derivation failed".into()))?;

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ticket_generation() {
        let handler = ZeroRttHandler::new(ZeroRttConfig::default());
        let ticket_id = generate_ticket_id();
        assert_eq!(ticket_id.len(), 16);
    }

    #[tokio::test]
    async fn test_replay_cache() {
        let mut cache = ReplayCache::new(Duration::from_secs(60));
        let hash = vec![1, 2, 3, 4];

        assert!(!cache.check_and_insert(hash.clone()));
        assert!(cache.check_and_insert(hash));
    }

    #[tokio::test]
    async fn test_early_data_encryption() {
        let secret = vec![0u8; 32];
        let data = b"early data test";

        let encrypted = encrypt_early_data(data, &secret).unwrap();
        let decrypted = decrypt_early_data(&encrypted, &secret).unwrap();

        assert_eq!(data.to_vec(), decrypted);
    }
}