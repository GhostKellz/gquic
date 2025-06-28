use super::{CryptoBackend, KeyPair, KeyType, PrivateKey, PublicKey, Signature, SignatureType};
use anyhow::Result;
use ring::{
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305, AES_256_GCM},
    digest,
    hkdf::{self, Prk},
    rand::{self, SecureRandom},
    signature::{self, Ed25519KeyPair, KeyPair as RingKeyPair},
};

pub struct RustlsBackend {
    rng: rand::SystemRandom,
}

impl RustlsBackend {
    pub fn new() -> Self {
        Self {
            rng: rand::SystemRandom::new(),
        }
    }
}

impl CryptoBackend for RustlsBackend {
    fn name(&self) -> &'static str {
        "rustls"
    }

    fn generate_keypair(&self, key_type: KeyType) -> Result<KeyPair> {
        match key_type {
            KeyType::Ed25519 => {
                let key_pair_doc = Ed25519KeyPair::generate_pkcs8(&self.rng)?;
                let key_pair = Ed25519KeyPair::from_pkcs8(key_pair_doc.as_ref())?;
                
                let private_key = PrivateKey {
                    data: key_pair_doc.as_ref().to_vec(),
                    key_type: KeyType::Ed25519,
                };
                
                let public_key = PublicKey {
                    data: key_pair.public_key().as_ref().to_vec(),
                    key_type: KeyType::Ed25519,
                };
                
                Ok(KeyPair {
                    private_key,
                    public_key,
                    key_type,
                })
            }
            
            KeyType::Secp256k1 | KeyType::Secp256r1 => {
                // Ring doesn't support secp256k1 or secp256r1 directly
                // For a production implementation, you'd use a different library like secp256k1-rs
                Err(anyhow::anyhow!(
                    "Secp256k1/Secp256r1 not supported in rustls backend, use gcrypt backend"
                ))
            }
        }
    }

    fn import_private_key(&self, key_data: &[u8], key_type: KeyType) -> Result<PrivateKey> {
        match key_type {
            KeyType::Ed25519 => {
                // Validate the key by trying to parse it
                let _key_pair = Ed25519KeyPair::from_pkcs8(key_data)?;
                
                Ok(PrivateKey {
                    data: key_data.to_vec(),
                    key_type,
                })
            }
            
            KeyType::Secp256k1 | KeyType::Secp256r1 => {
                Err(anyhow::anyhow!(
                    "Secp256k1/Secp256r1 not supported in rustls backend"
                ))
            }
        }
    }

    fn export_public_key(&self, private_key: &PrivateKey) -> Result<PublicKey> {
        match private_key.key_type {
            KeyType::Ed25519 => {
                let key_pair = Ed25519KeyPair::from_pkcs8(&private_key.data)?;
                
                Ok(PublicKey {
                    data: key_pair.public_key().as_ref().to_vec(),
                    key_type: private_key.key_type,
                })
            }
            
            KeyType::Secp256k1 | KeyType::Secp256r1 => {
                Err(anyhow::anyhow!(
                    "Secp256k1/Secp256r1 not supported in rustls backend"
                ))
            }
        }
    }

    fn sign(&self, private_key: &PrivateKey, data: &[u8]) -> Result<Signature> {
        match private_key.key_type {
            KeyType::Ed25519 => {
                let key_pair = Ed25519KeyPair::from_pkcs8(&private_key.data)?;
                let signature_bytes = key_pair.sign(data);
                
                Ok(Signature {
                    data: signature_bytes.as_ref().to_vec(),
                    signature_type: SignatureType::Ed25519,
                })
            }
            
            KeyType::Secp256k1 | KeyType::Secp256r1 => {
                Err(anyhow::anyhow!(
                    "Secp256k1/Secp256r1 not supported in rustls backend"
                ))
            }
        }
    }

    fn verify(&self, public_key: &PublicKey, data: &[u8], signature: &Signature) -> Result<bool> {
        match public_key.key_type {
            KeyType::Ed25519 => {
                if signature.signature_type != SignatureType::Ed25519 {
                    return Ok(false);
                }
                
                let public_key_bytes = signature::UnparsedPublicKey::new(
                    &signature::ED25519,
                    &public_key.data,
                );
                
                match public_key_bytes.verify(data, &signature.data) {
                    Ok(()) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
            
            KeyType::Secp256k1 | KeyType::Secp256r1 => {
                Err(anyhow::anyhow!(
                    "Secp256k1/Secp256r1 not supported in rustls backend"
                ))
            }
        }
    }

    fn derive_key(&self, secret: &[u8], salt: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>> {
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt);
        let prk = salt.extract(secret);
        
        let mut output = vec![0u8; length];
        prk.expand(&[info], MyLength(length))?.fill(&mut output)?;
        
        Ok(output)
    }

    fn encrypt_aead(&self, key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let algorithm = if key.len() == 32 {
            &CHACHA20_POLY1305
        } else {
            &AES_256_GCM
        };
        
        let unbound_key = UnboundKey::new(algorithm, key)?;
        let less_safe_key = LessSafeKey::new(unbound_key);
        
        let nonce = Nonce::try_assume_unique_for_key(nonce)?;
        let aad = Aad::from(aad);
        
        let mut in_out = plaintext.to_vec();
        less_safe_key.seal_in_place_append_tag(nonce, aad, &mut in_out)?;
        
        Ok(in_out)
    }

    fn decrypt_aead(&self, key: &[u8], nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let algorithm = if key.len() == 32 {
            &CHACHA20_POLY1305
        } else {
            &AES_256_GCM
        };
        
        let unbound_key = UnboundKey::new(algorithm, key)?;
        let less_safe_key = LessSafeKey::new(unbound_key);
        
        let nonce = Nonce::try_assume_unique_for_key(nonce)?;
        let aad = Aad::from(aad);
        
        let mut in_out = ciphertext.to_vec();
        let plaintext = less_safe_key.open_in_place(nonce, aad, &mut in_out)?;
        
        Ok(plaintext.to_vec())
    }
}

impl Default for RustlsBackend {
    fn default() -> Self {
        Self::new()
    }
}

// Helper struct for HKDF output length
struct MyLength(usize);

impl hkdf::KeyType for MyLength {
    fn len(&self) -> usize {
        self.0
    }
}