//! TLS 1.3 integration for QUIC handshake
//!
//! This module provides TLS 1.3 handshake functionality specifically
//! tailored for QUIC transport as defined in RFC 9001.

use crate::quic::error::{QuicError, Result};
use bytes::{Bytes, BytesMut};
use std::collections::VecDeque;
use std::sync::Arc;

#[cfg(feature = "rustls-tls")]
use rustls::{
    ClientConnection, ServerConnection,
};

/// TLS handshake states for QUIC
#[derive(Debug, Clone, PartialEq)]
pub enum TlsState {
    /// Initial state before handshake starts
    Initial,
    /// Waiting for peer's handshake data
    WantRead,
    /// Have handshake data to send to peer
    WantWrite,
    /// Handshake is complete
    Connected,
    /// Handshake failed
    Failed(String),
}

/// Encryption levels for QUIC packets
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EncryptionLevel {
    /// Initial packets (connection establishment)
    Initial,
    /// Early data (0-RTT)
    EarlyData,
    /// Handshake packets
    Handshake,
    /// Application data (1-RTT)
    Application,
}

/// QUIC packet protection keys
#[derive(Debug, Clone)]
pub struct PacketKeys {
    /// Header protection key
    pub header: [u8; 32],
    /// Packet encryption/decryption keys
    pub packet: [u8; 32],
}

/// TLS connection wrapper for QUIC
pub enum TlsConnection {
    #[cfg(feature = "rustls-tls")]
    Client(ClientConnection),
    #[cfg(feature = "rustls-tls")]
    Server(ServerConnection),
    #[cfg(not(feature = "rustls-tls"))]
    Disabled,
}

impl std::fmt::Debug for TlsConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "rustls-tls")]
            TlsConnection::Client(_) => f.debug_struct("TlsConnection::Client").finish(),
            #[cfg(feature = "rustls-tls")]
            TlsConnection::Server(_) => f.debug_struct("TlsConnection::Server").finish(),
            #[cfg(not(feature = "rustls-tls"))]
            TlsConnection::Disabled => f.debug_struct("TlsConnection::Disabled").finish(),
        }
    }
}

/// QUIC TLS handshake manager
#[derive(Debug)]
pub struct QuicTls {
    connection: TlsConnection,
    state: TlsState,
    handshake_data: VecDeque<Bytes>,
    /// Outgoing handshake data to be sent
    pub outgoing_handshake: BytesMut,
    /// Packet protection keys by encryption level
    keys: std::collections::HashMap<EncryptionLevel, PacketKeys>,
}

impl QuicTls {
    /// Create a new client TLS connection
    #[cfg(feature = "rustls-tls")]
    pub fn new_client(server_name: &str) -> Result<Self> {
        use rustls::pki_types::ServerName;

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();

        let server_name = ServerName::try_from(server_name)
            .map_err(|e| QuicError::Tls(format!("Invalid server name: {}", e)))?;

        let conn = ClientConnection::new(Arc::new(config), server_name)
            .map_err(|e| QuicError::Tls(format!("Failed to create client connection: {}", e)))?;

        Ok(Self {
            connection: TlsConnection::Client(conn),
            state: TlsState::Initial,
            handshake_data: VecDeque::new(),
            outgoing_handshake: BytesMut::new(),
            keys: std::collections::HashMap::new(),
        })
    }

    /// Create a new server TLS connection
    #[cfg(feature = "rustls-tls")]
    pub fn new_server(config: Arc<rustls::ServerConfig>) -> Result<Self> {
        let conn = ServerConnection::new(config)
            .map_err(|e| QuicError::Tls(format!("Failed to create server connection: {}", e)))?;

        Ok(Self {
            connection: TlsConnection::Server(conn),
            state: TlsState::Initial,
            handshake_data: VecDeque::new(),
            outgoing_handshake: BytesMut::new(),
            keys: std::collections::HashMap::new(),
        })
    }

    /// Create a disabled TLS connection (when rustls feature is not enabled)
    #[cfg(not(feature = "rustls-tls"))]
    pub fn new_client(_server_name: &str) -> Result<Self> {
        Ok(Self {
            connection: TlsConnection::Disabled,
            state: TlsState::Failed("TLS not enabled".to_string()),
            handshake_data: VecDeque::new(),
            outgoing_handshake: BytesMut::new(),
            keys: std::collections::HashMap::new(),
        })
    }

    #[cfg(not(feature = "rustls-tls"))]
    pub fn new_server(_config: ()) -> Result<Self> {
        Ok(Self {
            connection: TlsConnection::Disabled,
            state: TlsState::Failed("TLS not enabled".to_string()),
            handshake_data: VecDeque::new(),
            outgoing_handshake: BytesMut::new(),
            keys: std::collections::HashMap::new(),
        })
    }

    /// Get current TLS state
    pub fn state(&self) -> &TlsState {
        &self.state
    }

    /// Check if handshake is complete
    pub fn is_handshake_complete(&self) -> bool {
        matches!(self.state, TlsState::Connected)
    }

    /// Process incoming handshake data
    pub fn process_handshake_data(&mut self, data: &[u8], level: EncryptionLevel) -> Result<()> {
        #[cfg(feature = "rustls-tls")]
        {
            match &mut self.connection {
                TlsConnection::Client(conn) | TlsConnection::Server(conn) => {
                    // Simplified handshake processing for now
                    // In a real implementation, would use rustls QUIC API properly

                    // Store handshake data
                    self.handshake_data.push_back(Bytes::copy_from_slice(data));

                    // Simple state progression for demo
                    match self.state {
                        TlsState::Initial => self.state = TlsState::WantWrite,
                        TlsState::WantRead => self.state = TlsState::Connected,
                        _ => {}
                    }

                    // Generate some dummy response data
                    if self.state == TlsState::WantWrite {
                        self.outgoing_handshake.extend_from_slice(b"handshake_response");
                    }

                    Ok(())
                }
                #[cfg(not(feature = "rustls-tls"))]
                TlsConnection::Disabled => {
                    Err(QuicError::Tls("TLS not enabled".to_string()))
                }
            }
        }
        #[cfg(not(feature = "rustls-tls"))]
        {
            Err(QuicError::Tls("TLS not enabled".to_string()))
        }
    }

    /// Get outgoing handshake data to send to peer
    pub fn get_handshake_data(&mut self) -> Option<Bytes> {
        if self.outgoing_handshake.is_empty() {
            None
        } else {
            Some(self.outgoing_handshake.split().freeze())
        }
    }

    /// Start the TLS handshake
    pub fn start_handshake(&mut self) -> Result<()> {
        #[cfg(feature = "rustls-tls")]
        {
            match &mut self.connection {
                TlsConnection::Client(_conn) => {
                    // For clients, we start the handshake and get initial data
                    self.outgoing_handshake.extend_from_slice(b"client_hello");
                    self.state = TlsState::WantWrite;
                    Ok(())
                }
                TlsConnection::Server(_) => {
                    // Servers wait for client hello
                    self.state = TlsState::WantRead;
                    Ok(())
                }
            }
        }
        #[cfg(not(feature = "rustls-tls"))]
        {
            Err(QuicError::Tls("TLS not enabled".to_string()))
        }
    }

    /// Extract packet protection keys from completed handshake
    #[cfg(feature = "rustls-tls")]
    fn extract_keys(&mut self) -> Result<()> {
        // This is a placeholder - in a real implementation, you would extract
        // the actual keys from the TLS connection for packet protection
        // The rustls QUIC API provides methods to get these keys
        Ok(())
    }

    /// Get packet protection keys for encryption level
    pub fn get_keys(&self, level: EncryptionLevel) -> Option<&PacketKeys> {
        self.keys.get(&level)
    }

    /// Protect (encrypt) a packet header
    pub fn protect_header(&self, level: EncryptionLevel, header: &mut [u8], sample: &[u8]) -> Result<()> {
        if let Some(keys) = self.keys.get(&level) {
            // Apply header protection using the header protection key
            // This is a simplified implementation
            for (i, byte) in header.iter_mut().enumerate() {
                if i < sample.len() {
                    *byte ^= sample[i];
                }
            }
            Ok(())
        } else {
            Err(QuicError::Crypto("No keys available for encryption level".to_string()))
        }
    }

    /// Unprotect (decrypt) a packet header
    pub fn unprotect_header(&self, level: EncryptionLevel, header: &mut [u8], sample: &[u8]) -> Result<()> {
        // Header protection is symmetric, so unprotection is the same as protection
        self.protect_header(level, header, sample)
    }

    /// Encrypt packet payload
    pub fn encrypt_payload(&self, level: EncryptionLevel, plaintext: &[u8], packet_number: u64) -> Result<Vec<u8>> {
        if let Some(_keys) = self.keys.get(&level) {
            // Placeholder encryption - in real implementation, use AEAD encryption
            // with the packet keys and packet number as additional data
            let mut ciphertext = plaintext.to_vec();

            // Simple XOR encryption for demo (NOT secure!)
            for (i, byte) in ciphertext.iter_mut().enumerate() {
                *byte ^= (packet_number as u8).wrapping_add(i as u8);
            }

            // Add authentication tag (placeholder)
            ciphertext.extend_from_slice(&[0u8; 16]); // 16-byte auth tag

            Ok(ciphertext)
        } else {
            Err(QuicError::Crypto("No keys available for encryption level".to_string()))
        }
    }

    /// Decrypt packet payload
    pub fn decrypt_payload(&self, level: EncryptionLevel, ciphertext: &[u8], packet_number: u64) -> Result<Vec<u8>> {
        if let Some(_keys) = self.keys.get(&level) {
            if ciphertext.len() < 16 {
                return Err(QuicError::Crypto("Ciphertext too short".to_string()));
            }

            // Remove authentication tag
            let (encrypted_data, _auth_tag) = ciphertext.split_at(ciphertext.len() - 16);

            // Simple XOR decryption for demo (NOT secure!)
            let mut plaintext = encrypted_data.to_vec();
            for (i, byte) in plaintext.iter_mut().enumerate() {
                *byte ^= (packet_number as u8).wrapping_add(i as u8);
            }

            Ok(plaintext)
        } else {
            Err(QuicError::Crypto("No keys available for encryption level".to_string()))
        }
    }
}

/// TLS configuration builder for QUIC
pub struct TlsConfigBuilder {
    #[cfg(feature = "rustls-tls")]
    client_config: Option<rustls::ClientConfig>,
    #[cfg(feature = "rustls-tls")]
    server_config: Option<rustls::ServerConfig>,
}

impl TlsConfigBuilder {
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "rustls-tls")]
            client_config: None,
            #[cfg(feature = "rustls-tls")]
            server_config: None,
        }
    }

    /// Build a client configuration
    #[cfg(feature = "rustls-tls")]
    pub fn build_client(&self) -> Arc<rustls::ClientConfig> {
        if let Some(ref config) = self.client_config {
            Arc::new(config.clone())
        } else {
            // Default client configuration
            Arc::new(
                rustls::ClientConfig::builder()
                    .with_root_certificates(rustls::RootCertStore::empty())
                    .with_no_client_auth()
            )
        }
    }

    /// Build a server configuration
    #[cfg(feature = "rustls-tls")]
    pub fn build_server(&self) -> Result<Arc<rustls::ServerConfig>> {
        if let Some(ref config) = self.server_config {
            Ok(Arc::new(config.clone()))
        } else {
            Err(QuicError::Tls("No server certificate configured".to_string()))
        }
    }

    #[cfg(not(feature = "rustls-tls"))]
    pub fn build_client(&self) -> () {
        ()
    }

    #[cfg(not(feature = "rustls-tls"))]
    pub fn build_server(&self) -> Result<()> {
        Err(QuicError::Tls("TLS not enabled".to_string()))
    }
}

impl Default for TlsConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}