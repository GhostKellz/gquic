use anyhow::{Result, anyhow};
use bytes::{Bytes, BytesMut, BufMut};
use ring::{aead, hkdf, hmac};
use std::sync::Arc;

use super::{CryptoBackend, KeyType, KeyPair, PrivateKey, PublicKey, Signature};

/// QUIC-specific crypto operations
pub struct QuicCrypto {
    backend: Arc<dyn CryptoBackend>,
    initial_salt: [u8; 20],
}

impl QuicCrypto {
    pub fn new(backend: Arc<dyn CryptoBackend>) -> Self {
        // QUIC version 1 initial salt
        let initial_salt = [
            0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
            0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
        ];
        
        Self {
            backend,
            initial_salt,
        }
    }
    
    /// Derive initial secrets for client and server
    pub fn derive_initial_secrets(&self, connection_id: &[u8]) -> Result<InitialSecrets> {
        let initial_secret = self.backend.derive_key(
            connection_id,
            &self.initial_salt,
            b"",
            32
        )?;
        
        let client_initial_secret = self.backend.derive_key(
            &initial_secret,
            b"",
            b"client in",
            32
        )?;
        
        let server_initial_secret = self.backend.derive_key(
            &initial_secret,
            b"",
            b"server in",
            32
        )?;
        
        Ok(InitialSecrets {
            client: client_initial_secret,
            server: server_initial_secret,
        })
    }
    
    /// Derive packet protection keys from a secret
    pub fn derive_packet_keys(&self, secret: &[u8]) -> Result<PacketKeys> {
        let key = self.backend.derive_key(secret, b"", b"quic key", 16)?;
        let iv = self.backend.derive_key(secret, b"", b"quic iv", 12)?;
        let hp_key = self.backend.derive_key(secret, b"", b"quic hp", 16)?;
        
        Ok(PacketKeys {
            key: key.try_into().map_err(|_| anyhow!("Invalid key length"))?,
            iv: iv.try_into().map_err(|_| anyhow!("Invalid IV length"))?,
            hp_key: hp_key.try_into().map_err(|_| anyhow!("Invalid HP key length"))?,
        })
    }
    
    /// Encrypt a QUIC packet payload
    pub fn encrypt_packet(
        &self,
        keys: &PacketKeys,
        packet_number: u64,
        header: &[u8],
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        // Construct nonce by XORing packet number with IV
        let mut nonce = keys.iv;
        let pn_bytes = packet_number.to_be_bytes();
        for (i, &b) in pn_bytes.iter().enumerate() {
            nonce[12 - pn_bytes.len() + i] ^= b;
        }
        
        // Encrypt payload with AEAD
        let ciphertext = self.backend.encrypt_aead(
            &keys.key,
            &nonce,
            header,
            payload
        )?;
        
        Ok(ciphertext)
    }
    
    /// Decrypt a QUIC packet payload
    pub fn decrypt_packet(
        &self,
        keys: &PacketKeys,
        packet_number: u64,
        header: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        // Construct nonce
        let mut nonce = keys.iv;
        let pn_bytes = packet_number.to_be_bytes();
        for (i, &b) in pn_bytes.iter().enumerate() {
            nonce[12 - pn_bytes.len() + i] ^= b;
        }
        
        // Decrypt payload
        let plaintext = self.backend.decrypt_aead(
            &keys.key,
            &nonce,
            header,
            ciphertext
        )?;
        
        Ok(plaintext)
    }
    
    /// Apply header protection
    pub fn protect_header(&self, keys: &PacketKeys, sample: &[u8], first_byte: &mut u8, pn_bytes: &mut [u8]) -> Result<()> {
        if sample.len() < 16 {
            return Err(anyhow!("Sample too short for header protection"));
        }
        
        // Simple XOR-based header protection (simplified for now)
        // In production, this would use AES-ECB or ChaCha20
        let mask = &self.backend.derive_key(&keys.hp_key, &sample[..16], b"", 5)?;
        
        // Apply mask to first byte (preserve fixed bits)
        if *first_byte & 0x80 == 0x80 {
            // Long header: mask bottom 4 bits
            *first_byte ^= mask[0] & 0x0f;
        } else {
            // Short header: mask bottom 5 bits
            *first_byte ^= mask[0] & 0x1f;
        }
        
        // Apply mask to packet number
        for (i, pn_byte) in pn_bytes.iter_mut().enumerate() {
            *pn_byte ^= mask[i + 1];
        }
        
        Ok(())
    }
    
    /// Remove header protection
    pub fn unprotect_header(&self, keys: &PacketKeys, sample: &[u8], first_byte: &mut u8, pn_bytes: &mut [u8]) -> Result<()> {
        // Header protection is symmetric, so we just call protect_header
        self.protect_header(keys, sample, first_byte, pn_bytes)
    }
    
    /// Update keys for key rotation
    pub fn update_keys(&self, _current_keys: &PacketKeys, current_secret: &[u8]) -> Result<(PacketKeys, Vec<u8>)> {
        let new_secret = self.backend.derive_key(
            current_secret,
            b"",
            b"quic ku",
            32
        )?;
        
        let new_keys = self.derive_packet_keys(&new_secret)?;

        Ok((new_keys, new_secret))
    }

    /// Generate a random nonce for encryption
    pub fn generate_nonce(&self) -> Result<Vec<u8>> {
        // Generate a 12-byte nonce for AES-GCM
        let mut nonce = vec![0u8; 12];
        // Use ring's SecureRandom to fill the nonce
        use ring::rand::{SecureRandom, SystemRandom};
        let rng = SystemRandom::new();
        rng.fill(&mut nonce).map_err(|_| anyhow!("Failed to generate nonce"))?;
        Ok(nonce)
    }

    /// Get access to the underlying crypto backend
    pub fn backend(&self) -> &Arc<dyn CryptoBackend> {
        &self.backend
    }
}

/// Initial secrets for client and server
#[derive(Debug)]
pub struct InitialSecrets {
    pub client: Vec<u8>,
    pub server: Vec<u8>,
}

/// Packet protection keys
#[derive(Debug, Clone)]
pub struct PacketKeys {
    pub key: [u8; 16],      // AEAD key
    pub iv: [u8; 12],       // AEAD IV
    pub hp_key: [u8; 16],   // Header protection key
}

/// Key phase for 1-RTT packets
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KeyPhase {
    Zero,
    One,
}

impl KeyPhase {
    pub fn flip(&self) -> Self {
        match self {
            KeyPhase::Zero => KeyPhase::One,
            KeyPhase::One => KeyPhase::Zero,
        }
    }
}

/// Encryption level for QUIC packets
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EncryptionLevel {
    Initial,
    Handshake,
    OneRtt,
}

/// Transport parameters for TLS extension
#[derive(Debug, Clone)]
pub struct TransportParameters {
    pub max_idle_timeout: u64,
    pub max_udp_payload_size: u64,
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub ack_delay_exponent: u8,
    pub max_ack_delay: u64,
    pub disable_active_migration: bool,
    pub active_connection_id_limit: u64,
}

impl Default for TransportParameters {
    fn default() -> Self {
        Self {
            max_idle_timeout: 30_000, // 30 seconds
            max_udp_payload_size: 65527,
            initial_max_data: 10_485_760, // 10 MB
            initial_max_stream_data_bidi_local: 1_048_576, // 1 MB
            initial_max_stream_data_bidi_remote: 1_048_576,
            initial_max_stream_data_uni: 1_048_576,
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 100,
            ack_delay_exponent: 3,
            max_ack_delay: 25,
            disable_active_migration: false,
            active_connection_id_limit: 2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_key_phase_flip() {
        assert_eq!(KeyPhase::Zero.flip(), KeyPhase::One);
        assert_eq!(KeyPhase::One.flip(), KeyPhase::Zero);
    }
}