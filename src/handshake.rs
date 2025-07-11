//! QUIC handshake implementation

use crate::crypto::{CryptoBackend, PublicKey, PrivateKey, SharedSecret, default_crypto_backend};
use crate::{ConnectionId, QuicResult, QuicError, Frame};
use bytes::Bytes;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq)]
pub enum HandshakeState {
    Initial,
    ClientHello,
    ServerHello,
    ClientFinished,
    Established,
    Failed(String),
}

/// QUIC handshake manager
#[derive(Clone)]
pub struct QuicHandshake {
    state: HandshakeState,
    crypto_backend: Arc<dyn CryptoBackend>,
    local_keypair: Option<(PublicKey, PrivateKey)>,
    peer_public_key: Option<PublicKey>,
    shared_secret: Option<SharedSecret>,
    connection_id: ConnectionId,
}

impl std::fmt::Debug for QuicHandshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicHandshake")
            .field("state", &self.state)
            .field("crypto_backend", &"<dyn CryptoBackend>")
            .field("local_keypair", &self.local_keypair.is_some())
            .field("peer_public_key", &self.peer_public_key.is_some())
            .field("shared_secret", &self.shared_secret.is_some())
            .field("connection_id", &self.connection_id)
            .finish()
    }
}

impl QuicHandshake {
    pub fn new(connection_id: ConnectionId) -> Self {
        Self {
            state: HandshakeState::Initial,
            crypto_backend: default_crypto_backend(),
            local_keypair: None,
            peer_public_key: None,
            shared_secret: None,
            connection_id,
        }
    }
    
    pub fn with_crypto_backend(connection_id: ConnectionId, backend: Arc<dyn CryptoBackend>) -> Self {
        Self {
            state: HandshakeState::Initial,
            crypto_backend: backend,
            local_keypair: None,
            peer_public_key: None,
            shared_secret: None,
            connection_id,
        }
    }
    
    /// Start client handshake
    pub async fn start_client_handshake(&mut self) -> QuicResult<Frame> {
        // Generate local keypair
        let (public_key, private_key) = self.crypto_backend.generate_keypair()?;
        self.local_keypair = Some((public_key.clone(), private_key));
        self.state = HandshakeState::ClientHello;
        
        // Create ClientHello frame
        Ok(Frame::CryptoHandshake {
            key_exchange: Bytes::from(public_key.as_bytes().to_vec()),
        })
    }
    
    /// Handle server response to ClientHello
    pub async fn handle_server_hello(&mut self, frame: Frame) -> QuicResult<Frame> {
        match frame {
            Frame::CryptoHandshake { key_exchange } => {
                let peer_public_key = PublicKey(key_exchange.to_vec());
                self.peer_public_key = Some(peer_public_key.clone());
                
                // Perform key exchange
                if let Some((_, ref private_key)) = self.local_keypair {
                    let shared_secret = self.crypto_backend.key_exchange(private_key, &peer_public_key)?;
                    self.shared_secret = Some(shared_secret);
                    self.state = HandshakeState::ClientFinished;
                    
                    // Create ClientFinished frame with signature
                    let signature = self.crypto_backend.sign(
                        self.connection_id.as_bytes(),
                        private_key
                    )?;
                    
                    Ok(Frame::CryptoAuth {
                        signature: Bytes::from(signature.as_bytes().to_vec()),
                        public_key: Bytes::from(self.local_keypair.as_ref().unwrap().0.as_bytes().to_vec()),
                    })
                } else {
                    self.state = HandshakeState::Failed("No local keypair".to_string());
                    Err(QuicError::KeyExchangeFailed("No local keypair".to_string()))
                }
            }
            _ => {
                self.state = HandshakeState::Failed("Invalid server hello".to_string());
                Err(QuicError::KeyExchangeFailed("Invalid server hello frame".to_string()))
            }
        }
    }
    
    /// Handle server handshake as server
    pub async fn handle_client_hello(&mut self, frame: Frame) -> QuicResult<Frame> {
        match frame {
            Frame::CryptoHandshake { key_exchange } => {
                // Store peer public key
                let peer_public_key = PublicKey(key_exchange.to_vec());
                self.peer_public_key = Some(peer_public_key.clone());
                
                // Generate server keypair
                let (public_key, private_key) = self.crypto_backend.generate_keypair()?;
                self.local_keypair = Some((public_key.clone(), private_key.clone()));
                
                // Perform key exchange
                let shared_secret = self.crypto_backend.key_exchange(&private_key, &peer_public_key)?;
                self.shared_secret = Some(shared_secret);
                self.state = HandshakeState::ServerHello;
                
                // Create ServerHello frame
                Ok(Frame::CryptoHandshake {
                    key_exchange: Bytes::from(public_key.as_bytes().to_vec()),
                })
            }
            _ => {
                self.state = HandshakeState::Failed("Invalid client hello".to_string());
                Err(QuicError::KeyExchangeFailed("Invalid client hello frame".to_string()))
            }
        }
    }
    
    /// Handle client finished message
    pub async fn handle_client_finished(&mut self, frame: Frame) -> QuicResult<()> {
        match frame {
            Frame::CryptoAuth { signature, public_key } => {
                // Verify the signature
                let is_valid = self.crypto_backend.verify(
                    self.connection_id.as_bytes(),
                    &crate::crypto::Signature(signature.to_vec()),
                    &PublicKey(public_key.to_vec())
                )?;
                
                if is_valid {
                    self.state = HandshakeState::Established;
                    Ok(())
                } else {
                    self.state = HandshakeState::Failed("Invalid signature".to_string());
                    Err(QuicError::AuthenticationFailed("Invalid client signature".to_string()))
                }
            }
            _ => {
                self.state = HandshakeState::Failed("Invalid client finished".to_string());
                Err(QuicError::KeyExchangeFailed("Invalid client finished frame".to_string()))
            }
        }
    }
    
    /// Check if handshake is complete
    pub fn is_established(&self) -> bool {
        matches!(self.state, HandshakeState::Established)
    }
    
    /// Get current handshake state
    pub fn state(&self) -> &HandshakeState {
        &self.state
    }
    
    /// Get shared secret (only available after successful handshake)
    pub fn shared_secret(&self) -> Option<&SharedSecret> {
        self.shared_secret.as_ref()
    }
    
    /// Encrypt data using the established shared secret
    pub fn encrypt_data(&self, data: &[u8]) -> QuicResult<Vec<u8>> {
        if let Some(secret) = &self.shared_secret {
            let nonce = self.crypto_backend.generate_nonce()?;
            let mut encrypted = self.crypto_backend.encrypt(data, secret, &nonce)?;
            encrypted.extend_from_slice(&nonce);
            Ok(encrypted)
        } else {
            Err(QuicError::Crypto("No shared secret available".to_string()))
        }
    }
    
    /// Decrypt data using the established shared secret
    pub fn decrypt_data(&self, data: &[u8]) -> QuicResult<Vec<u8>> {
        if let Some(secret) = &self.shared_secret {
            if data.len() < 12 {
                return Err(QuicError::Crypto("Data too short for nonce".to_string()));
            }
            
            let (encrypted_data, nonce) = data.split_at(data.len() - 12);
            self.crypto_backend.decrypt(encrypted_data, secret, nonce)
        } else {
            Err(QuicError::Crypto("No shared secret available".to_string()))
        }
    }
}
