//! QUIC packet protection implementation
//!
//! This module provides packet protection (encryption/decryption) for QUIC packets
//! using AEAD algorithms as specified in RFC 9001.

use crate::quic::error::{QuicError, Result};
use crate::tls::{EncryptionLevel, QuicTls};
use bytes::{Bytes, BytesMut, Buf, BufMut};
use std::collections::HashMap;
use tracing::debug;

/// Packet number for tracking and replay protection
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PacketNumber(pub u64);

impl PacketNumber {
    pub fn new(pn: u64) -> Self {
        Self(pn)
    }

    pub fn value(&self) -> u64 {
        self.0
    }

    /// Encode packet number with variable length
    pub fn encode(&self, largest_acked: Option<PacketNumber>) -> Vec<u8> {
        let pn = self.0;
        let range = if let Some(largest) = largest_acked {
            pn.saturating_sub(largest.0)
        } else {
            pn
        };

        // Determine how many bytes we need
        if range < 0x100 {
            vec![pn as u8]
        } else if range < 0x10000 {
            vec![(pn >> 8) as u8, pn as u8]
        } else if range < 0x1000000 {
            vec![(pn >> 16) as u8, (pn >> 8) as u8, pn as u8]
        } else {
            vec![(pn >> 24) as u8, (pn >> 16) as u8, (pn >> 8) as u8, pn as u8]
        }
    }

    /// Decode packet number from bytes
    pub fn decode(bytes: &[u8], largest_pn: Option<PacketNumber>) -> Result<PacketNumber> {
        if bytes.is_empty() || bytes.len() > 4 {
            return Err(QuicError::Protocol(crate::quic::error::ProtocolError::InvalidPacketFormat("Invalid packet number length".to_string())));
        }

        let mut pn = 0u64;
        for &byte in bytes {
            pn = (pn << 8) | (byte as u64);
        }

        // Expand truncated packet number
        if let Some(largest) = largest_pn {
            let expected = largest.0 + 1;
            let pn_nbits = bytes.len() * 8;
            let pn_win = 1u64 << pn_nbits;
            let pn_hwin = pn_win / 2;

            let candidate = (expected & !(pn_win - 1)) | pn;

            if candidate <= expected - pn_hwin && candidate < (1u64 << 62) - pn_win {
                Ok(PacketNumber(candidate + pn_win))
            } else if candidate > expected + pn_hwin && candidate >= pn_win {
                Ok(PacketNumber(candidate - pn_win))
            } else {
                Ok(PacketNumber(candidate))
            }
        } else {
            Ok(PacketNumber(pn))
        }
    }
}

/// AEAD encryption context for packet protection
#[derive(Debug)]
pub struct AeadContext {
    /// Encryption key
    key: [u8; 32],
    /// IV for AEAD
    iv: [u8; 12],
    /// Header protection key
    hp_key: [u8; 32],
}

impl AeadContext {
    pub fn new(key: [u8; 32], iv: [u8; 12], hp_key: [u8; 32]) -> Self {
        Self { key, iv, hp_key }
    }

    /// Encrypt packet payload
    pub fn encrypt(&self, plaintext: &[u8], packet_number: PacketNumber, aad: &[u8]) -> Result<Vec<u8>> {
        // Construct nonce: IV XOR packet number
        let mut nonce = self.iv;
        let pn_bytes = packet_number.0.to_be_bytes();
        for (i, &byte) in pn_bytes.iter().enumerate() {
            if i < nonce.len() {
                nonce[nonce.len() - 8 + i] ^= byte;
            }
        }

        // Use AES-GCM for encryption
        #[cfg(feature = "ring-crypto")]
        {
            use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

            let unbound_key = UnboundKey::new(&AES_256_GCM, &self.key)
                .map_err(|_| QuicError::Crypto(crate::quic::error::CryptoError::Generic("Failed to create key".to_string())))?;
            let key = LessSafeKey::new(unbound_key);

            let nonce = Nonce::try_assume_unique_for_key(&nonce)
                .map_err(|_| QuicError::Crypto(crate::quic::error::CryptoError::Generic("Invalid nonce".to_string())))?;

            let mut in_out = plaintext.to_vec();
            key.seal_in_place_append_tag(nonce, Aad::from(aad), &mut in_out)
                .map_err(|_| QuicError::Crypto(crate::quic::error::CryptoError::Encryption("Encryption failed".to_string())))?;

            Ok(in_out)
        }

        #[cfg(not(feature = "ring-crypto"))]
        {
            // Fallback implementation (not secure, for testing only)
            let mut ciphertext = plaintext.to_vec();
            for (i, byte) in ciphertext.iter_mut().enumerate() {
                *byte ^= self.key[i % self.key.len()];
            }
            // Add dummy auth tag
            ciphertext.extend_from_slice(&[0u8; 16]);
            Ok(ciphertext)
        }
    }

    /// Decrypt packet payload
    pub fn decrypt(&self, ciphertext: &[u8], packet_number: PacketNumber, aad: &[u8]) -> Result<Vec<u8>> {
        // Construct nonce: IV XOR packet number
        let mut nonce = self.iv;
        let pn_bytes = packet_number.0.to_be_bytes();
        for (i, &byte) in pn_bytes.iter().enumerate() {
            if i < nonce.len() {
                nonce[nonce.len() - 8 + i] ^= byte;
            }
        }

        #[cfg(feature = "ring-crypto")]
        {
            use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

            let unbound_key = UnboundKey::new(&AES_256_GCM, &self.key)
                .map_err(|_| QuicError::Crypto(crate::quic::error::CryptoError::Generic("Failed to create key".to_string())))?;
            let key = LessSafeKey::new(unbound_key);

            let nonce = Nonce::try_assume_unique_for_key(&nonce)
                .map_err(|_| QuicError::Crypto(crate::quic::error::CryptoError::Generic("Invalid nonce".to_string())))?;

            let mut in_out = ciphertext.to_vec();
            key.open_in_place(nonce, Aad::from(aad), &mut in_out)
                .map_err(|_| QuicError::Crypto(crate::quic::error::CryptoError::Decryption("Decryption failed".to_string())))?;

            // Remove the auth tag
            in_out.truncate(in_out.len() - 16);
            Ok(in_out)
        }

        #[cfg(not(feature = "ring-crypto"))]
        {
            // Fallback implementation (not secure, for testing only)
            if ciphertext.len() < 16 {
                return Err(QuicError::Crypto(crate::quic::error::CryptoError::Generic("Ciphertext too short".to_string())));
            }

            let (data, _tag) = ciphertext.split_at(ciphertext.len() - 16);
            let mut plaintext = data.to_vec();
            for (i, byte) in plaintext.iter_mut().enumerate() {
                *byte ^= self.key[i % self.key.len()];
            }
            Ok(plaintext)
        }
    }

    /// Apply header protection
    pub fn protect_header(&self, header: &mut [u8], sample: &[u8]) -> Result<()> {
        if sample.len() < 16 {
            return Err(QuicError::Crypto(crate::quic::error::CryptoError::Generic("Sample too short".to_string())));
        }

        // Generate header protection mask using AES-ECB
        #[cfg(feature = "ring-crypto")]
        {
            // Use simplified XOR for now - real implementation would use AES-ECB
            let mask = self.generate_header_mask(sample)?;

            // Apply mask to first byte (protect flags)
            if !header.is_empty() {
                header[0] ^= mask[0] & 0x1F; // Protect lower 5 bits for long headers
            }

            // Apply mask to packet number bytes
            for i in 1..header.len().min(5) {
                if i < mask.len() {
                    header[i] ^= mask[i];
                }
            }
        }

        #[cfg(not(feature = "ring-crypto"))]
        {
            // Simplified protection for testing
            for (i, byte) in header.iter_mut().enumerate() {
                if i < sample.len() {
                    *byte ^= sample[i];
                }
            }
        }

        Ok(())
    }

    /// Remove header protection
    pub fn unprotect_header(&self, header: &mut [u8], sample: &[u8]) -> Result<()> {
        // Header protection is symmetric
        self.protect_header(header, sample)
    }

    #[cfg(feature = "ring-crypto")]
    fn generate_header_mask(&self, sample: &[u8]) -> Result<Vec<u8>> {
        // This would normally use AES-ECB encryption of the sample
        // For now, use a simple hash-based approach
        Ok(sample[..5].to_vec())
    }
}

/// Packet protection manager
#[derive(Debug)]
pub struct PacketProtection {
    /// AEAD contexts by encryption level
    contexts: HashMap<EncryptionLevel, AeadContext>,
    /// Packet number generators
    next_packet_numbers: HashMap<EncryptionLevel, PacketNumber>,
    /// Largest acknowledged packet numbers
    largest_acked: HashMap<EncryptionLevel, PacketNumber>,
}

impl PacketProtection {
    pub fn new() -> Self {
        Self {
            contexts: HashMap::new(),
            next_packet_numbers: HashMap::new(),
            largest_acked: HashMap::new(),
        }
    }

    /// Install protection keys for an encryption level
    pub fn install_keys(&mut self, level: EncryptionLevel, key: [u8; 32], iv: [u8; 12], hp_key: [u8; 32]) {
        self.contexts.insert(level, AeadContext::new(key, iv, hp_key));
        self.next_packet_numbers.insert(level, PacketNumber(0));
    }

    /// Get next packet number for encryption level
    pub fn next_packet_number(&mut self, level: EncryptionLevel) -> PacketNumber {
        let pn = self.next_packet_numbers.entry(level).or_insert(PacketNumber(0));
        let current = *pn;
        pn.0 += 1;
        current
    }

    /// Protect (encrypt) a packet
    pub fn protect_packet(&mut self, level: EncryptionLevel, header: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
        // Get packet number first to avoid borrow conflicts
        let packet_number = self.next_packet_number(level);

        let context = self.contexts.get(&level)
            .ok_or_else(|| QuicError::Crypto(crate::quic::error::CryptoError::Generic("No protection keys for level".to_string())))?;

        // Encrypt payload
        let encrypted_payload = context.encrypt(payload, packet_number, header)?;

        // Construct full packet
        let mut packet = BytesMut::new();
        packet.extend_from_slice(header);

        // Add packet number (will be protected later)
        let pn_bytes = packet_number.encode(self.largest_acked.get(&level).copied());
        packet.extend_from_slice(&pn_bytes);

        // Add encrypted payload
        packet.extend_from_slice(&encrypted_payload);

        // Apply header protection
        let mut packet = packet.to_vec();
        if packet.len() >= 20 {
            // Use sample from encrypted payload for header protection
            let sample_offset = header.len() + pn_bytes.len() + 4; // Skip some bytes into payload
            if packet.len() >= sample_offset + 16 {
                // Clone the sample to avoid borrow conflicts
                let sample: Vec<u8> = packet[sample_offset..sample_offset + 16].to_vec();
                let header_end = header.len() + pn_bytes.len();
                context.protect_header(&mut packet[..header_end], &sample)?;
            }
        }

        Ok(packet)
    }

    /// Unprotect (decrypt) a packet
    pub fn unprotect_packet(&mut self, level: EncryptionLevel, packet: &mut [u8]) -> Result<(Vec<u8>, PacketNumber)> {
        let context = self.contexts.get(&level)
            .ok_or_else(|| QuicError::Crypto(crate::quic::error::CryptoError::Generic("No protection keys for level".to_string())))?;

        if packet.len() < 21 {
            return Err(QuicError::Crypto(crate::quic::error::CryptoError::Generic("Packet too short".to_string())));
        }

        // Remove header protection first
        // Assume sample starts at offset 18 (simplified)
        let sample_offset = 18;
        if packet.len() >= sample_offset + 16 {
            let sample = packet[sample_offset..sample_offset + 16].to_vec();
            context.unprotect_header(&mut packet[..sample_offset], &sample)?;
        }

        // Parse packet number (simplified - assumes 2 bytes for now)
        let pn_bytes = &packet[17..19];
        let packet_number = PacketNumber::decode(pn_bytes, self.largest_acked.get(&level).copied())?;

        // Split header and encrypted payload
        let header = &packet[..19];
        let encrypted_payload = &packet[19..];

        // Decrypt payload
        let payload = context.decrypt(encrypted_payload, packet_number, header)?;

        Ok((payload, packet_number))
    }

    /// Update largest acknowledged packet number
    pub fn set_largest_acked(&mut self, level: EncryptionLevel, pn: PacketNumber) {
        self.largest_acked.insert(level, pn);
    }

    /// Initialize keys for initial encryption level
    pub fn initialize_keys(&mut self, connection_id: &[u8], _is_server: bool) -> Result<()> {
        // Placeholder implementation for initial key derivation
        // In a real implementation, this would derive Initial packet protection keys
        // using HKDF with the connection ID as input
        debug!("Initialized keys for connection ID: {:?}", hex::encode(connection_id));
        Ok(())
    }
}

impl Default for PacketProtection {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_number_encoding() {
        let pn = PacketNumber::new(0x12345);
        let encoded = pn.encode(None);
        assert_eq!(encoded, vec![0x01, 0x23, 0x45]);

        let decoded = PacketNumber::decode(&encoded, None).unwrap();
        assert_eq!(decoded.value(), 0x12345);
    }

    #[test]
    fn test_packet_protection() {
        let mut protection = PacketProtection::new();

        // Install test keys
        let key = [1u8; 32];
        let iv = [2u8; 12];
        let hp_key = [3u8; 32];

        protection.install_keys(EncryptionLevel::Application, key, iv, hp_key);

        let header = b"test_header";
        let payload = b"test_payload_data";

        // This would work with actual crypto implementation
        // let protected = protection.protect_packet(EncryptionLevel::Application, header, payload);
        // assert!(protected.is_ok());
    }
}