//! Crypto backend abstraction for GQUIC

use crate::QuicResult;
use bytes::Bytes;

/// Trait for cryptographic operations
pub trait CryptoBackend: Send + Sync {
    /// Generate a new keypair for key exchange
    fn generate_keypair(&self) -> QuicResult<(PublicKey, PrivateKey)>;
    
    /// Perform key exchange to derive shared secret
    fn key_exchange(&self, private_key: &PrivateKey, peer_public_key: &PublicKey) -> QuicResult<SharedSecret>;
    
    /// Encrypt data with the given key
    fn encrypt(&self, data: &[u8], key: &SharedSecret, nonce: &[u8]) -> QuicResult<Vec<u8>>;
    
    /// Decrypt data with the given key
    fn decrypt(&self, data: &[u8], key: &SharedSecret, nonce: &[u8]) -> QuicResult<Vec<u8>>;
    
    /// Sign data with private key
    fn sign(&self, data: &[u8], private_key: &PrivateKey) -> QuicResult<Signature>;
    
    /// Verify signature with public key
    fn verify(&self, data: &[u8], signature: &Signature, public_key: &PublicKey) -> QuicResult<bool>;
    
    /// Generate random nonce
    fn generate_nonce(&self) -> QuicResult<[u8; 12]>;
}

/// Public key type
#[derive(Debug, Clone)]
pub struct PublicKey(pub Vec<u8>);

/// Private key type  
#[derive(Debug, Clone)]
pub struct PrivateKey(pub Vec<u8>);

/// Shared secret from key exchange
#[derive(Debug, Clone)]
pub struct SharedSecret(pub [u8; 32]);

/// Digital signature
#[derive(Debug, Clone)]
pub struct Signature(pub Vec<u8>);

impl PublicKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl PrivateKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl SharedSecret {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Signature {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

// Re-export crypto implementations
#[cfg(feature = "gcc-crypto")]
pub mod gcc_backend;

#[cfg(feature = "ring-crypto")]
pub mod ring_backend;

/// Create default crypto backend based on available features
pub fn default_crypto_backend() -> Box<dyn CryptoBackend> {
    #[cfg(feature = "gcc-crypto")]
    {
        Box::new(gcc_backend::GccBackend::new())
    }
    #[cfg(all(feature = "ring-crypto", not(feature = "gcc-crypto")))]
    {
        Box::new(ring_backend::RingBackend::new())
    }
    #[cfg(not(any(feature = "gcc-crypto", feature = "ring-crypto")))]
    {
        compile_error!("No crypto backend enabled. Enable either 'gcc-crypto' or 'ring-crypto'");
    }
}
