//! QUIC connection management

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

use crate::crypto::{CryptoBackend, SharedSecret, default_crypto_backend};
use crate::handshake::QuicHandshake;
use crate::QuicResult;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionId(pub Vec<u8>);

impl ConnectionId {
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }
    
    pub fn random() -> Self {
        Self(vec![1, 2, 3, 4]) // Placeholder
    }
    
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct Connection {
    id: ConnectionId,
    remote_addr: SocketAddr,
    socket: Arc<UdpSocket>,
    crypto_backend: Arc<dyn CryptoBackend>,
    handshake: Option<QuicHandshake>,
    shared_secret: Option<SharedSecret>,
}

impl Connection {
    pub fn new(id: ConnectionId, remote_addr: SocketAddr, socket: Arc<UdpSocket>) -> Self {
        Self { 
            id, 
            remote_addr, 
            socket,
            crypto_backend: default_crypto_backend(),
            handshake: None,
            shared_secret: None,
        }
    }
    
    pub fn with_crypto_backend(
        id: ConnectionId, 
        remote_addr: SocketAddr, 
        socket: Arc<UdpSocket>,
        crypto_backend: Arc<dyn CryptoBackend>
    ) -> Self {
        Self { 
            id, 
            remote_addr, 
            socket,
            crypto_backend,
            handshake: None,
            shared_secret: None,
        }
    }
    
    pub fn id(&self) -> &ConnectionId {
        &self.id
    }
    
    /// Initialize handshake for this connection
    pub fn init_handshake(&mut self) {
        self.handshake = Some(QuicHandshake::with_crypto_backend(
            self.id.clone(),
            self.crypto_backend.clone()
        ));
    }
    
    /// Get mutable reference to handshake
    pub fn handshake_mut(&mut self) -> Option<&mut QuicHandshake> {
        self.handshake.as_mut()
    }
    
    /// Check if handshake is established and update connection state
    pub fn update_crypto_state(&mut self) {
        if let Some(handshake) = &self.handshake {
            if handshake.is_established() {
                self.shared_secret = handshake.shared_secret().cloned();
            }
        }
    }
    
    pub async fn send(&self, data: &[u8]) -> QuicResult<()> {
        self.socket.send_to(data, self.remote_addr).await?;
        Ok(())
    }
    
    /// Send data with real GCC encryption
    pub async fn send_encrypted(&self, data: &[u8]) -> QuicResult<()> {
        if let Some(handshake) = &self.handshake {
            if handshake.is_established() {
                let encrypted_data = handshake.encrypt_data(data)?;
                self.socket.send_to(&encrypted_data, self.remote_addr).await?;
                Ok(())
            } else {
                Err(crate::QuicError::Crypto("Handshake not established".to_string()))
            }
        } else {
            Err(crate::QuicError::Crypto("No handshake initialized".to_string()))
        }
    }
    
    /// Send data with legacy key-based encryption (for compatibility)
    pub async fn send_encrypted_with_key(&self, data: &[u8], key: &[u8]) -> QuicResult<()> {
        if key.len() < 32 {
            return Err(crate::QuicError::Crypto("Key too short".to_string()));
        }
        
        let shared_secret = SharedSecret({
            let mut secret = [0u8; 32];
            secret.copy_from_slice(&key[..32]);
            secret
        });
        
        let nonce = self.crypto_backend.generate_nonce()?;
        let encrypted_data = self.crypto_backend.encrypt(data, &shared_secret, &nonce)?;
        
        // Append nonce to encrypted data
        let mut payload = encrypted_data;
        payload.extend_from_slice(&nonce);
        
        self.socket.send_to(&payload, self.remote_addr).await?;
        Ok(())
    }
    
    /// Receive and decrypt data using established handshake
    pub async fn receive_decrypted(&self) -> QuicResult<Vec<u8>> {
        let mut buf = vec![0u8; 65535];
        let (len, _) = self.socket.recv_from(&mut buf).await?;
        buf.truncate(len);
        
        if let Some(handshake) = &self.handshake {
            if handshake.is_established() {
                handshake.decrypt_data(&buf)
            } else {
                Err(crate::QuicError::Crypto("Handshake not established".to_string()))
            }
        } else {
            Err(crate::QuicError::Crypto("No handshake initialized".to_string()))
        }
    }
    
    /// Receive and decrypt data with legacy key-based decryption (for compatibility)
    pub async fn receive_decrypted_with_key(&self, key: &[u8]) -> QuicResult<Vec<u8>> {
        let mut buf = vec![0u8; 65535];
        let (len, _) = self.socket.recv_from(&mut buf).await?;
        buf.truncate(len);
        
        if buf.len() < 12 {
            return Err(crate::QuicError::Crypto("Data too short for nonce".to_string()));
        }
        
        if key.len() < 32 {
            return Err(crate::QuicError::Crypto("Key too short".to_string()));
        }
        
        let shared_secret = SharedSecret({
            let mut secret = [0u8; 32];
            secret.copy_from_slice(&key[..32]);
            secret
        });
        
        // Extract nonce from end of payload
        let (encrypted_data, nonce) = buf.split_at(buf.len() - 12);
        let decrypted_data = self.crypto_backend.decrypt(encrypted_data, &shared_secret, nonce)?;
        Ok(decrypted_data)
    }
    
    /// Get connection statistics for monitoring
    pub fn stats(&self) -> ConnectionStats {
        ConnectionStats {
            id: self.id.clone(),
            remote_addr: self.remote_addr,
            packets_sent: 0, // Placeholder - would track in real implementation
            packets_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionStats {
    pub id: ConnectionId,
    pub remote_addr: SocketAddr,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}
