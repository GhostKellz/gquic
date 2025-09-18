//! Crypto backend abstraction for GQUIC

use anyhow::Result;
use std::sync::Arc;

/// Unified trait for QUIC cryptographic operations
pub trait CryptoBackend: Send + Sync + std::fmt::Debug {
    fn name(&self) -> &'static str;

    // Key generation and management
    fn generate_keypair(&self, key_type: KeyType) -> Result<KeyPair>;
    fn import_private_key(&self, key_data: &[u8], key_type: KeyType) -> Result<PrivateKey>;
    fn export_public_key(&self, private_key: &PrivateKey) -> Result<PublicKey>;

    // Digital signatures
    fn sign(&self, private_key: &PrivateKey, data: &[u8]) -> Result<Signature>;
    fn verify(&self, public_key: &PublicKey, data: &[u8], signature: &Signature) -> Result<bool>;

    // Key derivation (HKDF)
    fn derive_key(&self, secret: &[u8], salt: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>>;

    // AEAD encryption/decryption for packet protection
    fn encrypt_aead(&self, key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>>;
    fn decrypt_aead(&self, key: &[u8], nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>>;
}

/// Supported cryptographic key types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Ed25519,
    Secp256r1,
    Secp256k1,
}

/// Public key with associated algorithm
#[derive(Debug, Clone)]
pub struct PublicKey {
    pub data: Vec<u8>,
    pub key_type: KeyType,
}

/// Private key with associated algorithm
#[derive(Debug, Clone)]
pub struct PrivateKey {
    pub data: Vec<u8>,
    pub key_type: KeyType,
}

/// Cryptographic key pair
#[derive(Debug, Clone)]
pub struct KeyPair {
    pub private_key: PrivateKey,
    pub public_key: PublicKey,
    pub key_type: KeyType,
}

/// Digital signature with type information
#[derive(Debug, Clone)]
pub struct Signature {
    pub data: Vec<u8>,
    pub signature_type: SignatureType,
}

/// Signature algorithm types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureType {
    Ed25519,
    EcdsaSecp256r1Sha256,
    EcdsaSecp256k1Sha256,
}

impl From<KeyType> for SignatureType {
    fn from(key_type: KeyType) -> Self {
        match key_type {
            KeyType::Ed25519 => SignatureType::Ed25519,
            KeyType::Secp256r1 => SignatureType::EcdsaSecp256r1Sha256,
            KeyType::Secp256k1 => SignatureType::EcdsaSecp256k1Sha256,
        }
    }
}

// Re-export crypto implementations
pub mod quic_crypto;
pub mod rustls_backend;

#[cfg(feature = "gcc-crypto")]
pub mod gcc_backend;

#[cfg(feature = "ring-crypto")]
pub mod ring_backend;

/// Create default crypto backend based on available features
pub fn default_crypto_backend() -> Arc<dyn CryptoBackend> {
    #[cfg(feature = "gcc-crypto")]
    {
        Arc::new(gcc_backend::GccBackend::new())
    }
    #[cfg(all(feature = "ring-crypto", not(feature = "gcc-crypto")))]
    {
        Arc::new(rustls_backend::RustlsBackend::new())
    }
    #[cfg(not(any(feature = "gcc-crypto", feature = "ring-crypto")))]
    {
        compile_error!("No crypto backend enabled. Enable either 'gcc-crypto' or 'ring-crypto'");
    }
}

/// Default QUIC crypto implementation
pub fn new_quic_crypto() -> quic_crypto::QuicCrypto {
    quic_crypto::QuicCrypto::new(default_crypto_backend())
}

/// TLS 1.3 integration for QUIC handshake
pub mod tls {
    use super::*;

    /// TLS handshake state for QUIC
    #[derive(Debug)]
    pub enum HandshakeState {
        Initial,
        InProgress,
        Complete,
        Failed(String),
    }

    /// TLS configuration for QUIC
    #[derive(Debug, Clone)]
    pub struct TlsConfig {
        pub server_name: Option<String>,
        pub alpn_protocols: Vec<Vec<u8>>,
        pub certificate_chain: Vec<Vec<u8>>,
        pub private_key: Option<PrivateKey>,
    }

    impl Default for TlsConfig {
        fn default() -> Self {
            Self {
                server_name: None,
                alpn_protocols: vec![b"h3".to_vec()], // HTTP/3
                certificate_chain: Vec::new(),
                private_key: None,
            }
        }
    }
}
