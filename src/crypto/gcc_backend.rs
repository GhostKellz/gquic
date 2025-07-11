//! GCC (GhostChain Crypto) backend implementation using gcrypt

use crate::crypto::{CryptoBackend, PublicKey, PrivateKey, SharedSecret, Signature};
use crate::{QuicResult, QuicError};

#[cfg(feature = "gcc-crypto")]
use gcrypt::protocols::{x25519, ed25519};
use gcrypt::rand_core;

#[cfg(feature = "gcc-crypto")]
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm,
};

/// GCC crypto backend using gcrypt for Curve25519 and AES-GCM for symmetric encryption
pub struct GccBackend {
    #[cfg(feature = "gcc-crypto")]
    _inner: (),
}

impl GccBackend {
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "gcc-crypto")]
            _inner: (),
        }
    }
}

impl CryptoBackend for GccBackend {
    fn generate_keypair(&self) -> QuicResult<(PublicKey, PrivateKey)> {
        #[cfg(feature = "gcc-crypto")]
        {
            // Generate X25519 keypair using gcrypt
            let secret_key = x25519::SecretKey::generate(&mut rand_core::OsRng);
            let public_key = secret_key.public_key();
            
            Ok((
                PublicKey(public_key.to_bytes().to_vec()),
                PrivateKey(secret_key.to_bytes().to_vec())
            ))
        }
        #[cfg(not(feature = "gcc-crypto"))]
        {
            Err(QuicError::Crypto("GCrypt backend not available".to_string()))
        }
    }
    
    fn key_exchange(&self, private_key: &PrivateKey, peer_public_key: &PublicKey) -> QuicResult<SharedSecret> {
        #[cfg(feature = "gcc-crypto")]
        {
            if private_key.as_bytes().len() != 32 || peer_public_key.as_bytes().len() != 32 {
                return Err(QuicError::Crypto("Invalid key length".to_string()));
            }
            
            let mut private_bytes = [0u8; 32];
            private_bytes.copy_from_slice(private_key.as_bytes());
            
            let mut public_bytes = [0u8; 32];
            public_bytes.copy_from_slice(peer_public_key.as_bytes());
            
            // Use gcrypt X25519 key exchange
            let secret_key = x25519::SecretKey::from_bytes(&private_bytes);
            let gcrypt_public_key = x25519::PublicKey::from_bytes(&public_bytes)
                .map_err(|e| QuicError::Crypto(format!("Invalid public key: {:?}", e)))?;
            
            let shared_secret = secret_key.diffie_hellman(&gcrypt_public_key)
                .map_err(|e| QuicError::Crypto(format!("Key exchange failed: {:?}", e)))?;
            
            Ok(SharedSecret(shared_secret.to_bytes()))
        }
        #[cfg(not(feature = "gcc-crypto"))]
        {
            Err(QuicError::Crypto("GCrypt backend not available".to_string()))
        }
    }
    
    fn encrypt(&self, data: &[u8], key: &SharedSecret, nonce: &[u8]) -> QuicResult<Vec<u8>> {
        #[cfg(feature = "gcc-crypto")]
        {
            if nonce.len() != 12 {
                return Err(QuicError::Crypto("Invalid nonce length".to_string()));
            }
            
            // Use AES-256-GCM
            let mut key_array = [0u8; 32];
            key_array.copy_from_slice(key.as_bytes());
            
            let mut nonce_array = [0u8; 12];
            nonce_array.copy_from_slice(nonce);
            
            let cipher = Aes256Gcm::new_from_slice(&key_array)
                .map_err(|e| QuicError::Crypto(format!("Invalid AES key: {:?}", e)))?;
            let nonce = aes_gcm::Nonce::from_slice(&nonce_array);
            
            cipher.encrypt(nonce, data)
                .map_err(|e| QuicError::Crypto(format!("AES-GCM encryption failed: {:?}", e)))
        }
        #[cfg(not(feature = "gcc-crypto"))]
        {
            Err(QuicError::Crypto("GCrypt backend not available".to_string()))
        }
    }
    
    fn decrypt(&self, data: &[u8], key: &SharedSecret, nonce: &[u8]) -> QuicResult<Vec<u8>> {
        #[cfg(feature = "gcc-crypto")]
        {
            if nonce.len() != 12 {
                return Err(QuicError::Crypto("Invalid nonce length".to_string()));
            }
            
            // Use AES-256-GCM
            let mut key_array = [0u8; 32];
            key_array.copy_from_slice(key.as_bytes());
            
            let mut nonce_array = [0u8; 12];
            nonce_array.copy_from_slice(nonce);
            
            let cipher = Aes256Gcm::new_from_slice(&key_array)
                .map_err(|e| QuicError::Crypto(format!("Invalid AES key: {:?}", e)))?;
            let nonce = aes_gcm::Nonce::from_slice(&nonce_array);
            
            cipher.decrypt(nonce, data)
                .map_err(|e| QuicError::Crypto(format!("AES-GCM decryption failed: {:?}", e)))
        }
        #[cfg(not(feature = "gcc-crypto"))]
        {
            Err(QuicError::Crypto("GCrypt backend not available".to_string()))
        }
    }
    
    fn sign(&self, data: &[u8], private_key: &PrivateKey) -> QuicResult<Signature> {
        #[cfg(feature = "gcc-crypto")]
        {
            if private_key.as_bytes().len() != 32 {
                return Err(QuicError::Crypto("Invalid private key length".to_string()));
            }
            
            let mut private_bytes = [0u8; 32];
            private_bytes.copy_from_slice(private_key.as_bytes());
            
            // Use gcrypt's Ed25519 signing
            let secret_key = ed25519::SecretKey::from_bytes(&private_bytes);
            
            let signature = secret_key.sign(data, &mut rand_core::OsRng);
            Ok(Signature(signature.to_bytes().to_vec()))
        }
        #[cfg(not(feature = "gcc-crypto"))]
        {
            Err(QuicError::Crypto("GCrypt backend not available".to_string()))
        }
    }
    
    fn verify(&self, data: &[u8], signature: &Signature, public_key: &PublicKey) -> QuicResult<bool> {
        #[cfg(feature = "gcc-crypto")]
        {
            if signature.as_bytes().len() != 64 || public_key.as_bytes().len() != 32 {
                return Err(QuicError::Crypto("Invalid signature or public key length".to_string()));
            }
            
            let mut signature_bytes = [0u8; 64];
            signature_bytes.copy_from_slice(signature.as_bytes());
            
            let mut public_key_bytes = [0u8; 32];
            public_key_bytes.copy_from_slice(public_key.as_bytes());
            
            let public_key = ed25519::PublicKey::from_bytes(&public_key_bytes)
                .map_err(|e| QuicError::Crypto(format!("Invalid public key: {:?}", e)))?;
            
            let mut signature_bytes_array = [0u8; 64];
            signature_bytes_array.copy_from_slice(signature.as_bytes());
            let signature = ed25519::Signature::from_bytes(&signature_bytes_array);
            
            Ok(public_key.verify(data, &signature).is_ok())
        }
        #[cfg(not(feature = "gcc-crypto"))]
        {
            Err(QuicError::Crypto("GCrypt backend not available".to_string()))
        }
    }
    
    fn generate_nonce(&self) -> QuicResult<[u8; 12]> {
        #[cfg(feature = "gcc-crypto")]
        {
            // Generate random nonce
            use rand_core::RngCore;
            let mut nonce = [0u8; 12];
            rand_core::OsRng.fill_bytes(&mut nonce);
            Ok(nonce)
        }
        #[cfg(not(feature = "gcc-crypto"))]
        {
            Err(QuicError::Crypto("GCrypt backend not available".to_string()))
        }
    }
}
