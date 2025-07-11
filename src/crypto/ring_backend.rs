//! Ring crypto backend implementation (fallback when GCC not available)

use crate::crypto::{CryptoBackend, PublicKey, PrivateKey, SharedSecret, Signature};
use crate::{QuicResult, QuicError};
use ::rand::RngCore;

#[cfg(feature = "ring-crypto")]
use {
    ring::rand,
    ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier, Signature as Ed25519Signature},
    aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}},
    ::rand::rngs::OsRng,
};

/// Ring crypto backend (fallback implementation)
#[derive(Debug)]
pub struct RingBackend {
    #[cfg(feature = "ring-crypto")]
    rng: rand::SystemRandom,
}

impl RingBackend {
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "ring-crypto")]
            rng: rand::SystemRandom::new(),
        }
    }
}

impl CryptoBackend for RingBackend {
    fn generate_keypair(&self) -> QuicResult<(PublicKey, PrivateKey)> {
        #[cfg(feature = "ring-crypto")]
        {
            let mut csprng = OsRng;
            let mut secret_key = [0u8; 32];
            csprng.fill_bytes(&mut secret_key);
            let signing_key = SigningKey::from_bytes(&secret_key);
            let verifying_key = signing_key.verifying_key();
            
            Ok((
                PublicKey(verifying_key.to_bytes().to_vec()),
                PrivateKey(signing_key.to_bytes().to_vec())
            ))
        }
        #[cfg(not(feature = "ring-crypto"))]
        {
            Err(QuicError::Crypto("Ring backend not available".to_string()))
        }
    }
    
    fn key_exchange(&self, private_key: &PrivateKey, _peer_public_key: &PublicKey) -> QuicResult<SharedSecret> {
        #[cfg(feature = "ring-crypto")]
        {
            // For now, return a placeholder implementation
            // TODO: Implement proper x25519 key exchange
            let mut shared_secret = [0u8; 32];
            shared_secret[..private_key.as_bytes().len().min(32)].copy_from_slice(
                &private_key.as_bytes()[..private_key.as_bytes().len().min(32)]
            );
            Ok(SharedSecret(shared_secret))
        }
        #[cfg(not(feature = "ring-crypto"))]
        {
            Err(QuicError::Crypto("Ring backend not available".to_string()))
        }
    }
    
    fn encrypt(&self, data: &[u8], key: &SharedSecret, nonce: &[u8]) -> QuicResult<Vec<u8>> {
        #[cfg(feature = "ring-crypto")]
        {
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_bytes()));
            let nonce = Nonce::from_slice(&nonce[..12]);
            
            cipher.encrypt(nonce, data)
                .map_err(|e| QuicError::Crypto(format!("Ring encryption failed: {}", e)))
        }
        #[cfg(not(feature = "ring-crypto"))]
        {
            Err(QuicError::Crypto("Ring backend not available".to_string()))
        }
    }
    
    fn decrypt(&self, data: &[u8], key: &SharedSecret, nonce: &[u8]) -> QuicResult<Vec<u8>> {
        #[cfg(feature = "ring-crypto")]
        {
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_bytes()));
            let nonce = Nonce::from_slice(&nonce[..12]);
            
            cipher.decrypt(nonce, data)
                .map_err(|e| QuicError::Crypto(format!("Ring decryption failed: {}", e)))
        }
        #[cfg(not(feature = "ring-crypto"))]
        {
            Err(QuicError::Crypto("Ring backend not available".to_string()))
        }
    }
    
    fn sign(&self, data: &[u8], private_key: &PrivateKey) -> QuicResult<Signature> {
        #[cfg(feature = "ring-crypto")]
        {
            let key_bytes: [u8; 32] = private_key.as_bytes().try_into()
                .map_err(|_| QuicError::Crypto("Invalid signing key length".to_string()))?;
            let signing_key = SigningKey::from_bytes(&key_bytes);
            
            let signature = signing_key.sign(data);
            Ok(Signature(signature.to_bytes().to_vec()))
        }
        #[cfg(not(feature = "ring-crypto"))]
        {
            Err(QuicError::Crypto("Ring backend not available".to_string()))
        }
    }
    
    fn verify(&self, data: &[u8], signature: &Signature, public_key: &PublicKey) -> QuicResult<bool> {
        #[cfg(feature = "ring-crypto")]
        {
            let verifying_key = VerifyingKey::from_bytes(public_key.as_bytes().try_into()
                .map_err(|_| QuicError::Crypto("Invalid public key length".to_string()))?)
                .map_err(|e| QuicError::Crypto(format!("Invalid public key: {}", e)))?;
                
            let signature = Ed25519Signature::try_from(signature.as_bytes())
                .map_err(|e| QuicError::Crypto(format!("Invalid signature: {}", e)))?;
                
            Ok(verifying_key.verify(data, &signature).is_ok())
        }
        #[cfg(not(feature = "ring-crypto"))]
        {
            Err(QuicError::Crypto("Ring backend not available".to_string()))
        }
    }
    
    fn generate_nonce(&self) -> QuicResult<[u8; 12]> {
        #[cfg(feature = "ring-crypto")]
        {
            let mut nonce = [0u8; 12];
            let mut rng = OsRng;
            rng.fill_bytes(&mut nonce);
            Ok(nonce)
        }
        #[cfg(not(feature = "ring-crypto"))]
        {
            Err(QuicError::Crypto("Ring backend not available".to_string()))
        }
    }
}
