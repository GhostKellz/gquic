//! Ring crypto backend implementation (fallback when GCC not available)

use crate::crypto::{CryptoBackend, PublicKey, PrivateKey, SharedSecret, Signature};
use crate::{QuicResult, QuicError};

#[cfg(feature = "ring-crypto")]
use {
    ring::rand,
    x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret},
    ed25519_dalek::{Keypair, Signer, Verifier},
    aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, NewAead}},
};

/// Ring crypto backend (fallback implementation)
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
            let mut csprng = rand::thread_rng();
            let keypair: Keypair = Keypair::generate(&mut csprng);
            
            Ok((
                PublicKey(keypair.public.to_bytes().to_vec()),
                PrivateKey(keypair.secret.to_bytes().to_vec())
            ))
        }
        #[cfg(not(feature = "ring-crypto"))]
        {
            Err(QuicError::Crypto("Ring backend not available".to_string()))
        }
    }
    
    fn key_exchange(&self, private_key: &PrivateKey, peer_public_key: &PublicKey) -> QuicResult<SharedSecret> {
        #[cfg(feature = "ring-crypto")]
        {
            let secret = StaticSecret::from(<[u8; 32]>::try_from(private_key.as_bytes())
                .map_err(|_| QuicError::Crypto("Invalid private key length".to_string()))?);
                
            let peer_public = X25519PublicKey::from(<[u8; 32]>::try_from(peer_public_key.as_bytes())
                .map_err(|_| QuicError::Crypto("Invalid public key length".to_string()))?);
                
            let shared_secret = secret.diffie_hellman(&peer_public);
            Ok(SharedSecret(*shared_secret.as_bytes()))
        }
        #[cfg(not(feature = "ring-crypto"))]
        {
            Err(QuicError::Crypto("Ring backend not available".to_string()))
        }
    }
    
    fn encrypt(&self, data: &[u8], key: &SharedSecret, nonce: &[u8]) -> QuicResult<Vec<u8>> {
        #[cfg(feature = "ring-crypto")]
        {
            let cipher = Aes256Gcm::new(Key::from_slice(key.as_bytes()));
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
            let cipher = Aes256Gcm::new(Key::from_slice(key.as_bytes()));
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
            let secret_key = ed25519_dalek::SecretKey::from_bytes(private_key.as_bytes())
                .map_err(|e| QuicError::Crypto(format!("Invalid signing key: {}", e)))?;
                
            let public_key = ed25519_dalek::PublicKey::from(&secret_key);
            let keypair = Keypair { secret: secret_key, public: public_key };
            
            let signature = keypair.sign(data);
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
            let public_key = ed25519_dalek::PublicKey::from_bytes(public_key.as_bytes())
                .map_err(|e| QuicError::Crypto(format!("Invalid public key: {}", e)))?;
                
            let signature = ed25519_dalek::Signature::try_from(signature.as_bytes())
                .map_err(|e| QuicError::Crypto(format!("Invalid signature: {}", e)))?;
                
            Ok(public_key.verify(data, &signature).is_ok())
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
            ring::rand::SecureRandom::fill(&self.rng, &mut nonce)
                .map_err(|e| QuicError::Crypto(format!("Ring nonce generation failed: {:?}", e)))?;
            Ok(nonce)
        }
        #[cfg(not(feature = "ring-crypto"))]
        {
            Err(QuicError::Crypto("Ring backend not available".to_string()))
        }
    }
}
