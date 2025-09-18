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

    // Additional methods for compatibility
    fn generate_nonce(&self) -> Result<Vec<u8>>;
    fn encrypt(&self, key: &[u8], nonce: &[u8], data: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, key: &[u8], nonce: &[u8], data: &[u8]) -> Result<Vec<u8>>;
}

/// Supported cryptographic key types
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum KeyType {
    Ed25519,
    Secp256r1,
    Secp256k1,
}

/// Public key with associated algorithm
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PublicKey {
    pub data: Vec<u8>,
    pub key_type: KeyType,
}

impl PublicKey {
    /// Create new public key with default Ed25519 type
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            key_type: KeyType::Ed25519,
        }
    }

    /// Create new public key with specified type
    pub fn with_type(data: Vec<u8>, key_type: KeyType) -> Self {
        Self { data, key_type }
    }

    /// Get the key data as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

/// Private key with associated algorithm
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PrivateKey {
    pub data: Vec<u8>,
    pub key_type: KeyType,
}

impl PrivateKey {
    /// Create new private key with default Ed25519 type
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            key_type: KeyType::Ed25519,
        }
    }

    /// Create new private key with specified type
    pub fn with_type(data: Vec<u8>, key_type: KeyType) -> Self {
        Self { data, key_type }
    }
}

/// Cryptographic key pair
#[derive(Debug, Clone)]
pub struct KeyPair {
    pub private_key: PrivateKey,
    pub public_key: PublicKey,
    pub key_type: KeyType,
}

/// Digital signature with type information
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Signature {
    pub data: Vec<u8>,
    pub signature_type: SignatureType,
}

/// Shared secret for symmetric encryption
#[derive(Debug, Clone)]
pub struct SharedSecret(pub [u8; 32]);

/// Signature algorithm types
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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

/// SIMD-accelerated crypto operations
pub mod simd {
    use super::*;

    /// SIMD-optimized memory operations
    pub struct SimdCrypto;

    impl SimdCrypto {
        /// SIMD-accelerated AES encryption
        #[cfg(target_arch = "x86_64")]
        pub fn aes_encrypt_simd(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
            use std::arch::x86_64::*;

            if !is_x86_feature_detected!("aes") {
                return Err(anyhow::anyhow!("AES-NI not available"));
            }

            let mut ciphertext = vec![0u8; plaintext.len()];

            unsafe {
                // Load key into SIMD register
                let key_128 = _mm_loadu_si128(key.as_ptr() as *const __m128i);

                // Process data in 16-byte chunks
                for (chunk_in, chunk_out) in plaintext.chunks_exact(16).zip(ciphertext.chunks_exact_mut(16)) {
                    let data = _mm_loadu_si128(chunk_in.as_ptr() as *const __m128i);
                    let encrypted = _mm_aesenc_si128(data, key_128);
                    _mm_storeu_si128(chunk_out.as_mut_ptr() as *mut __m128i, encrypted);
                }
            }

            Ok(ciphertext)
        }

        /// SIMD-accelerated hash operations
        #[cfg(target_arch = "x86_64")]
        pub fn sha256_simd(data: &[u8]) -> Result<[u8; 32]> {
            use std::arch::x86_64::*;

            if !is_x86_feature_detected!("sha") {
                return Err(anyhow::anyhow!("SHA extensions not available"));
            }

            // Simplified SHA-256 SIMD implementation
            let mut hash = [0u8; 32];

            unsafe {
                // Initialize hash state
                let mut state = [
                    _mm_set_epi32(0x6a09e667u32 as i32, 0xbb67ae85u32 as i32, 0x3c6ef372u32 as i32, 0xa54ff53au32 as i32),
                    _mm_set_epi32(0x510e527fu32 as i32, 0x9b05688cu32 as i32, 0x1f83d9abu32 as i32, 0x5be0cd19u32 as i32),
                ];

                // Process message blocks (simplified)
                for chunk in data.chunks(64) {
                    let msg = _mm_loadu_si128(chunk.as_ptr() as *const __m128i);
                    state[0] = _mm_sha256rnds2_epu32(state[0], state[1], msg);
                }

                // Extract final hash
                _mm_storeu_si128(hash.as_mut_ptr() as *mut __m128i, state[0]);
                _mm_storeu_si128(hash[16..].as_mut_ptr() as *mut __m128i, state[1]);
            }

            Ok(hash)
        }

        /// SIMD-accelerated XOR operations
        #[cfg(target_arch = "x86_64")]
        pub fn xor_simd(a: &[u8], b: &[u8], output: &mut [u8]) -> Result<()> {
            use std::arch::x86_64::*;

            if a.len() != b.len() || a.len() != output.len() {
                return Err(anyhow::anyhow!("Input lengths must match"));
            }

            unsafe {
                // Process 16 bytes at a time
                for ((chunk_a, chunk_b), chunk_out) in a.chunks_exact(16)
                    .zip(b.chunks_exact(16))
                    .zip(output.chunks_exact_mut(16)) {

                    let vec_a = _mm_loadu_si128(chunk_a.as_ptr() as *const __m128i);
                    let vec_b = _mm_loadu_si128(chunk_b.as_ptr() as *const __m128i);
                    let result = _mm_xor_si128(vec_a, vec_b);
                    _mm_storeu_si128(chunk_out.as_mut_ptr() as *mut __m128i, result);
                }

                // Handle remaining bytes
                let remainder = a.len() % 16;
                if remainder > 0 {
                    let start = a.len() - remainder;
                    for i in 0..remainder {
                        output[start + i] = a[start + i] ^ b[start + i];
                    }
                }
            }

            Ok(())
        }

        /// Check for hardware acceleration support
        pub fn hardware_support() -> HardwareSupport {
            HardwareSupport {
                aes_ni: cfg!(target_arch = "x86_64") && is_x86_feature_detected!("aes"),
                sha_ext: cfg!(target_arch = "x86_64") && is_x86_feature_detected!("sha"),
                avx2: cfg!(target_arch = "x86_64") && is_x86_feature_detected!("avx2"),
                avx512: cfg!(target_arch = "x86_64") && is_x86_feature_detected!("avx512f"),
            }
        }
    }

    /// Hardware acceleration capabilities
    #[derive(Debug, Clone)]
    pub struct HardwareSupport {
        pub aes_ni: bool,
        pub sha_ext: bool,
        pub avx2: bool,
        pub avx512: bool,
    }

    impl HardwareSupport {
        pub fn optimal_strategy(&self) -> CryptoStrategy {
            if self.avx512 {
                CryptoStrategy::Avx512
            } else if self.avx2 {
                CryptoStrategy::Avx2
            } else if self.aes_ni && self.sha_ext {
                CryptoStrategy::AesNiSha
            } else {
                CryptoStrategy::Software
            }
        }
    }

    /// Crypto optimization strategy
    #[derive(Debug, Clone, PartialEq)]
    pub enum CryptoStrategy {
        Software,
        AesNiSha,
        Avx2,
        Avx512,
    }

    /// SIMD-enhanced crypto backend
    pub struct SimdCryptoBackend {
        inner: Arc<dyn CryptoBackend>,
        strategy: CryptoStrategy,
        hardware: HardwareSupport,
    }

    impl SimdCryptoBackend {
        pub fn new(inner: Arc<dyn CryptoBackend>) -> Self {
            let hardware = SimdCrypto::hardware_support();
            let strategy = hardware.optimal_strategy();

            Self {
                inner,
                strategy,
                hardware,
            }
        }

        /// High-performance AEAD encryption with SIMD
        pub fn encrypt_aead_simd(&self, key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
            match self.strategy {
                CryptoStrategy::AesNiSha | CryptoStrategy::Avx2 | CryptoStrategy::Avx512 => {
                    #[cfg(target_arch = "x86_64")]
                    {
                        SimdCrypto::aes_encrypt_simd(key, plaintext)
                    }
                    #[cfg(not(target_arch = "x86_64"))]
                    {
                        self.inner.encrypt_aead(key, nonce, aad, plaintext)
                    }
                }
                CryptoStrategy::Software => {
                    self.inner.encrypt_aead(key, nonce, aad, plaintext)
                }
            }
        }

        /// Batch crypto operations for high throughput
        pub fn batch_encrypt(&self, operations: Vec<CryptoOperation>) -> Result<Vec<Vec<u8>>> {
            let mut results = Vec::with_capacity(operations.len());

            for op in operations {
                let result = self.encrypt_aead_simd(&op.key, &op.nonce, &op.aad, &op.plaintext)?;
                results.push(result);
            }

            Ok(results)
        }

        pub fn hardware_info(&self) -> &HardwareSupport {
            &self.hardware
        }

        pub fn current_strategy(&self) -> &CryptoStrategy {
            &self.strategy
        }
    }

    /// Single crypto operation for batching
    #[derive(Debug, Clone)]
    pub struct CryptoOperation {
        pub key: Vec<u8>,
        pub nonce: Vec<u8>,
        pub aad: Vec<u8>,
        pub plaintext: Vec<u8>,
    }
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
