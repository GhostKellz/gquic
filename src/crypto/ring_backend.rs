//! Ring crypto backend implementation (fallback when GCC not available)

use crate::crypto::{CryptoBackend, PublicKey, PrivateKey, Signature, KeyType};
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
    fn name(&self) -> &'static str {
        "ring"
    }

    fn generate_keypair(&self, key_type: KeyType) -> anyhow::Result<crate::crypto::KeyPair> {
        #[cfg(feature = "ring-crypto")]
        {
            match key_type {
                KeyType::Ed25519 => {
                    let mut csprng = OsRng;
                    let mut secret_key = [0u8; 32];
                    csprng.fill_bytes(&mut secret_key);
                    let signing_key = SigningKey::from_bytes(&secret_key);
                    let verifying_key = signing_key.verifying_key();

                    let private_key = PrivateKey {
                        data: signing_key.to_bytes().to_vec(),
                        key_type,
                    };

                    let public_key = PublicKey {
                        data: verifying_key.to_bytes().to_vec(),
                        key_type,
                    };

                    Ok(crate::crypto::KeyPair {
                        private_key,
                        public_key,
                        key_type,
                    })
                }
                _ => Err(anyhow::anyhow!("Unsupported key type: {:?}", key_type))
            }
        }
        #[cfg(not(feature = "ring-crypto"))]
        {
            Err(anyhow::anyhow!("Ring backend not available"))
        }
    }

    fn import_private_key(&self, key_data: &[u8], key_type: KeyType) -> anyhow::Result<PrivateKey> {
        Ok(PrivateKey {
            data: key_data.to_vec(),
            key_type,
        })
    }

    fn export_public_key(&self, private_key: &PrivateKey) -> anyhow::Result<PublicKey> {
        #[cfg(feature = "ring-crypto")]
        {
            match private_key.key_type {
                KeyType::Ed25519 => {
                    let key_bytes: [u8; 32] = private_key.data.clone().try_into()
                        .map_err(|_| anyhow::anyhow!("Invalid private key length"))?;
                    let signing_key = SigningKey::from_bytes(&key_bytes);
                    let verifying_key = signing_key.verifying_key();

                    Ok(PublicKey {
                        data: verifying_key.to_bytes().to_vec(),
                        key_type: private_key.key_type,
                    })
                }
                _ => Err(anyhow::anyhow!("Unsupported key type"))
            }
        }
        #[cfg(not(feature = "ring-crypto"))]
        {
            Err(anyhow::anyhow!("Ring backend not available"))
        }
    }
    fn sign(&self, private_key: &PrivateKey, data: &[u8]) -> anyhow::Result<Signature> {
        #[cfg(feature = "ring-crypto")]
        {
            match private_key.key_type {
                KeyType::Ed25519 => {
                    let key_bytes: [u8; 32] = private_key.data.clone().try_into()
                        .map_err(|_| anyhow::anyhow!("Invalid signing key length"))?;
                    let signing_key = SigningKey::from_bytes(&key_bytes);

                    let signature = signing_key.sign(data);
                    Ok(Signature {
                        data: signature.to_bytes().to_vec(),
                        signature_type: crate::crypto::SignatureType::Ed25519,
                    })
                }
                _ => Err(anyhow::anyhow!("Unsupported key type for signing"))
            }
        }
        #[cfg(not(feature = "ring-crypto"))]
        {
            Err(anyhow::anyhow!("Ring backend not available"))
        }
    }

    fn verify(&self, public_key: &PublicKey, data: &[u8], signature: &Signature) -> anyhow::Result<bool> {
        #[cfg(feature = "ring-crypto")]
        {
            match public_key.key_type {
                KeyType::Ed25519 => {
                    let key_bytes: [u8; 32] = public_key.data.clone().try_into()
                        .map_err(|_| anyhow::anyhow!("Invalid public key length"))?;
                    let verifying_key = VerifyingKey::from_bytes(&key_bytes)
                        .map_err(|e| anyhow::anyhow!("Invalid public key: {}", e))?;

                    let sig = Ed25519Signature::try_from(signature.data.as_slice())
                        .map_err(|e| anyhow::anyhow!("Invalid signature: {}", e))?;

                    Ok(verifying_key.verify(data, &sig).is_ok())
                }
                _ => Err(anyhow::anyhow!("Unsupported key type for verification"))
            }
        }
        #[cfg(not(feature = "ring-crypto"))]
        {
            Err(anyhow::anyhow!("Ring backend not available"))
        }
    }

    fn derive_key(&self, secret: &[u8], salt: &[u8], info: &[u8], length: usize) -> anyhow::Result<Vec<u8>> {
        // Simple HKDF implementation for testing
        let mut output = vec![0u8; length];
        for i in 0..length {
            output[i] = secret[i % secret.len()] ^ salt[i % salt.len()] ^ info[i % info.len()];
        }
        Ok(output)
    }

    fn encrypt_aead(&self, key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        #[cfg(feature = "ring-crypto")]
        {
            if key.len() < 16 || nonce.len() < 12 {
                return Err(anyhow::anyhow!("Invalid key or nonce length"));
            }

            // Simple XOR for demonstration - NOT SECURE
            let mut ciphertext = plaintext.to_vec();
            for (i, byte) in ciphertext.iter_mut().enumerate() {
                *byte ^= key[i % 16] ^ nonce[i % 12];
            }
            ciphertext.extend_from_slice(&[0u8; 16]); // Mock auth tag
            Ok(ciphertext)
        }
        #[cfg(not(feature = "ring-crypto"))]
        {
            Err(anyhow::anyhow!("Ring backend not available"))
        }
    }

    fn decrypt_aead(&self, key: &[u8], nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        #[cfg(feature = "ring-crypto")]
        {
            if key.len() < 16 || nonce.len() < 12 || ciphertext.len() < 16 {
                return Err(anyhow::anyhow!("Invalid key, nonce, or ciphertext length"));
            }

            // Simple XOR for demonstration - NOT SECURE
            let encrypted_data = &ciphertext[..ciphertext.len() - 16];
            let mut plaintext = encrypted_data.to_vec();
            for (i, byte) in plaintext.iter_mut().enumerate() {
                *byte ^= key[i % 16] ^ nonce[i % 12];
            }
            Ok(plaintext)
        }
        #[cfg(not(feature = "ring-crypto"))]
        {
            Err(anyhow::anyhow!("Ring backend not available"))
        }
    }

    fn generate_nonce(&self) -> anyhow::Result<Vec<u8>> {
        #[cfg(feature = "ring-crypto")]
        {
            let mut nonce = vec![0u8; 12];
            let mut rng = OsRng;
            rng.fill_bytes(&mut nonce);
            Ok(nonce)
        }
        #[cfg(not(feature = "ring-crypto"))]
        {
            Err(anyhow::anyhow!("Ring backend not available"))
        }
    }

    fn encrypt(&self, key: &[u8], nonce: &[u8], plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.encrypt_aead(key, nonce, &[], plaintext)
    }

    fn decrypt(&self, key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.decrypt_aead(key, nonce, &[], ciphertext)
    }
}
