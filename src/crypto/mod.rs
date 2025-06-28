use anyhow::Result;
use std::sync::Arc;

#[cfg(feature = "gcrypt-integration")]
pub mod gcrypt_backend;

pub mod rustls_backend;

pub use rustls_backend::*;

#[cfg(feature = "gcrypt-integration")]
pub use gcrypt_backend::*;

/// Cryptographic backend trait for pluggable crypto implementations
pub trait CryptoBackend: Send + Sync {
    fn name(&self) -> &'static str;
    
    // Key generation and management
    fn generate_keypair(&self, key_type: KeyType) -> Result<KeyPair>;
    fn import_private_key(&self, key_data: &[u8], key_type: KeyType) -> Result<PrivateKey>;
    fn export_public_key(&self, private_key: &PrivateKey) -> Result<PublicKey>;
    
    // Signing and verification
    fn sign(&self, private_key: &PrivateKey, data: &[u8]) -> Result<Signature>;
    fn verify(&self, public_key: &PublicKey, data: &[u8], signature: &Signature) -> Result<bool>;
    
    // Key derivation
    fn derive_key(&self, secret: &[u8], salt: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>>;
    
    // AEAD encryption/decryption
    fn encrypt_aead(&self, key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>>;
    fn decrypt_aead(&self, key: &[u8], nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Ed25519,
    Secp256k1,
    Secp256r1,
}

#[derive(Debug, Clone)]
pub struct KeyPair {
    pub private_key: PrivateKey,
    pub public_key: PublicKey,
    pub key_type: KeyType,
}

#[derive(Debug, Clone)]
pub struct PrivateKey {
    pub data: Vec<u8>,
    pub key_type: KeyType,
}

#[derive(Debug, Clone)]
pub struct PublicKey {
    pub data: Vec<u8>,
    pub key_type: KeyType,
}

#[derive(Debug, Clone)]
pub struct Signature {
    pub data: Vec<u8>,
    pub signature_type: SignatureType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureType {
    Ed25519,
    EcdsaSecp256k1,
    EcdsaSecp256r1,
}

impl From<KeyType> for SignatureType {
    fn from(key_type: KeyType) -> Self {
        match key_type {
            KeyType::Ed25519 => SignatureType::Ed25519,
            KeyType::Secp256k1 => SignatureType::EcdsaSecp256k1,
            KeyType::Secp256r1 => SignatureType::EcdsaSecp256r1,
        }
    }
}

/// Default crypto backend selection
pub fn default_backend() -> Arc<dyn CryptoBackend> {
    #[cfg(feature = "gcrypt-integration")]
    {
        Arc::new(gcrypt_backend::GcryptBackend::new())
    }
    
    #[cfg(not(feature = "gcrypt-integration"))]
    {
        Arc::new(rustls_backend::RustlsBackend::new())
    }
}

/// Create a specific backend
pub fn create_backend(name: &str) -> Result<Arc<dyn CryptoBackend>> {
    match name {
        "rustls" => Ok(Arc::new(rustls_backend::RustlsBackend::new())),
        
        #[cfg(feature = "gcrypt-integration")]
        "gcrypt" => Ok(Arc::new(gcrypt_backend::GcryptBackend::new())),
        
        _ => Err(anyhow::anyhow!("Unknown crypto backend: {}", name)),
    }
}