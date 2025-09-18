//! QUIC version negotiation implementation
//!
//! Implements RFC 9000 version negotiation to ensure compatible QUIC versions
//! between client and server, with support for future QUIC versions.

use std::collections::HashSet;
use crate::{QuicResult, QuicError};

/// QUIC version identifier (32-bit)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QuicVersion(u32);

impl QuicVersion {
    /// Create a new QUIC version
    pub fn new(version: u32) -> Self {
        Self(version)
    }

    /// Get the raw version number
    pub fn value(&self) -> u32 {
        self.0
    }

    /// Check if this is a reserved version for version negotiation testing
    pub fn is_reserved(&self) -> bool {
        // Reserved versions have the form 0x?a?a?a?a
        (self.0 & 0x0f0f0f0f) == 0x0a0a0a0a
    }

    /// Check if this version is compatible with another version
    pub fn is_compatible_with(&self, other: &QuicVersion) -> bool {
        self == other || self.is_draft_compatible_with(other)
    }

    /// Check draft version compatibility (for development)
    fn is_draft_compatible_with(&self, other: &QuicVersion) -> bool {
        // Draft versions might be compatible across minor revisions
        match (self.0, other.0) {
            // Draft versions
            (0xff000000..=0xffffffff, 0xff000000..=0xffffffff) => {
                // Same draft family
                (self.0 & 0xffff0000) == (other.0 & 0xffff0000)
            }
            _ => false,
        }
    }

    /// Convert to wire format (big-endian bytes)
    pub fn to_bytes(&self) -> [u8; 4] {
        self.0.to_be_bytes()
    }

    /// Create from wire format (big-endian bytes)
    pub fn from_bytes(bytes: [u8; 4]) -> Self {
        Self(u32::from_be_bytes(bytes))
    }
}

/// Standard QUIC versions
impl QuicVersion {
    /// QUIC version 1 (RFC 9000)
    pub const V1: QuicVersion = QuicVersion(0x00000001);

    /// QUIC version 2 (RFC 9369)
    pub const V2: QuicVersion = QuicVersion(0x6b3343cf);

    /// Draft versions for testing
    pub const DRAFT_29: QuicVersion = QuicVersion(0xff00001d);
    pub const DRAFT_32: QuicVersion = QuicVersion(0xff000020);

    /// Reserved version for version negotiation testing
    pub const RESERVED_VN: QuicVersion = QuicVersion(0x0a0a0a0a);

    /// Get all supported QUIC versions
    pub fn supported_versions() -> Vec<QuicVersion> {
        vec![
            QuicVersion::V1,
            QuicVersion::V2,
            QuicVersion::DRAFT_32,
            QuicVersion::DRAFT_29,
        ]
    }

    /// Get the preferred version (highest priority)
    pub fn preferred() -> QuicVersion {
        QuicVersion::V1
    }
}

/// Version negotiation packet
#[derive(Debug, Clone)]
pub struct VersionNegotiationPacket {
    /// Source connection ID
    pub scid: Vec<u8>,
    /// Destination connection ID
    pub dcid: Vec<u8>,
    /// List of supported versions
    pub supported_versions: Vec<QuicVersion>,
}

impl VersionNegotiationPacket {
    /// Create a new version negotiation packet
    pub fn new(scid: Vec<u8>, dcid: Vec<u8>, supported_versions: Vec<QuicVersion>) -> Self {
        Self {
            scid,
            dcid,
            supported_versions,
        }
    }

    /// Encode the packet to wire format
    pub fn encode(&self) -> Vec<u8> {
        let mut packet = Vec::new();

        // Packet header
        packet.push(0x80); // Long header with version negotiation flag
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Version = 0 for VN

        // Connection IDs
        packet.push(self.dcid.len() as u8);
        packet.extend_from_slice(&self.dcid);
        packet.push(self.scid.len() as u8);
        packet.extend_from_slice(&self.scid);

        // Supported versions
        for version in &self.supported_versions {
            packet.extend_from_slice(&version.to_bytes());
        }

        packet
    }

    /// Decode a version negotiation packet
    pub fn decode(data: &[u8]) -> QuicResult<Self> {
        if data.len() < 7 {
            return Err(QuicError::InvalidPacket("VN packet too short".to_string()));
        }

        let mut offset = 0;

        // Check packet type
        if data[offset] != 0x80 {
            return Err(QuicError::InvalidPacket("Invalid VN packet type".to_string()));
        }
        offset += 1;

        // Check version (should be 0)
        let version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        if version != 0 {
            return Err(QuicError::InvalidPacket("VN packet version must be 0".to_string()));
        }
        offset += 4;

        // Decode DCID
        if offset >= data.len() {
            return Err(QuicError::InvalidPacket("Missing DCID length".to_string()));
        }
        let dcid_len = data[offset] as usize;
        offset += 1;

        if offset + dcid_len > data.len() {
            return Err(QuicError::InvalidPacket("Invalid DCID length".to_string()));
        }
        let dcid = data[offset..offset + dcid_len].to_vec();
        offset += dcid_len;

        // Decode SCID
        if offset >= data.len() {
            return Err(QuicError::InvalidPacket("Missing SCID length".to_string()));
        }
        let scid_len = data[offset] as usize;
        offset += 1;

        if offset + scid_len > data.len() {
            return Err(QuicError::InvalidPacket("Invalid SCID length".to_string()));
        }
        let scid = data[offset..offset + scid_len].to_vec();
        offset += scid_len;

        // Decode supported versions
        let mut supported_versions = Vec::new();
        while offset + 4 <= data.len() {
            let version_bytes = [data[offset], data[offset + 1], data[offset + 2], data[offset + 3]];
            supported_versions.push(QuicVersion::from_bytes(version_bytes));
            offset += 4;
        }

        Ok(VersionNegotiationPacket {
            scid,
            dcid,
            supported_versions,
        })
    }
}

/// Version negotiation manager
#[derive(Debug)]
pub struct VersionNegotiationManager {
    /// Our supported versions (in preference order)
    supported_versions: Vec<QuicVersion>,
    /// Currently negotiated version
    current_version: Option<QuicVersion>,
    /// Whether we've completed version negotiation
    negotiation_complete: bool,
}

impl VersionNegotiationManager {
    /// Create a new version negotiation manager
    pub fn new() -> Self {
        Self {
            supported_versions: QuicVersion::supported_versions(),
            current_version: None,
            negotiation_complete: false,
        }
    }

    /// Create with custom supported versions
    pub fn with_versions(versions: Vec<QuicVersion>) -> Self {
        Self {
            supported_versions: versions,
            current_version: None,
            negotiation_complete: false,
        }
    }

    /// Get our supported versions
    pub fn supported_versions(&self) -> &[QuicVersion] {
        &self.supported_versions
    }

    /// Get the current negotiated version
    pub fn current_version(&self) -> Option<QuicVersion> {
        self.current_version
    }

    /// Check if version negotiation is complete
    pub fn is_complete(&self) -> bool {
        self.negotiation_complete
    }

    /// Handle an incoming Initial packet with a version
    pub fn handle_initial_version(&mut self, proposed_version: QuicVersion) -> QuicResult<VersionNegotiationResult> {
        // Check if the proposed version is supported
        if self.supported_versions.contains(&proposed_version) {
            self.current_version = Some(proposed_version);
            self.negotiation_complete = true;
            Ok(VersionNegotiationResult::Accepted(proposed_version))
        } else {
            // Send version negotiation packet
            Ok(VersionNegotiationResult::Rejected {
                supported_versions: self.supported_versions.clone(),
            })
        }
    }

    /// Handle a version negotiation packet
    pub fn handle_version_negotiation(&mut self, vn_packet: &VersionNegotiationPacket) -> QuicResult<QuicVersion> {
        // Find the best mutually supported version
        let mut best_version = None;

        // Prioritize by our preference order
        for our_version in &self.supported_versions {
            if vn_packet.supported_versions.contains(our_version) {
                best_version = Some(*our_version);
                break;
            }
        }

        match best_version {
            Some(version) => {
                self.current_version = Some(version);
                self.negotiation_complete = true;
                Ok(version)
            }
            None => Err(QuicError::Protocol("No mutually supported QUIC version".to_string())),
        }
    }

    /// Check if a version is supported
    pub fn is_version_supported(&self, version: QuicVersion) -> bool {
        self.supported_versions.contains(&version)
    }

    /// Get the best version for the given peer versions
    pub fn select_best_version(&self, peer_versions: &[QuicVersion]) -> Option<QuicVersion> {
        // Find the first version in our preference order that the peer supports
        self.supported_versions
            .iter()
            .find(|version| peer_versions.contains(version))
            .copied()
    }

    /// Create a version negotiation packet
    pub fn create_version_negotiation_packet(
        &self,
        scid: Vec<u8>,
        dcid: Vec<u8>,
    ) -> VersionNegotiationPacket {
        VersionNegotiationPacket::new(scid, dcid, self.supported_versions.clone())
    }

    /// Reset negotiation state
    pub fn reset(&mut self) {
        self.current_version = None;
        self.negotiation_complete = false;
    }

    /// Force a specific version (for testing)
    pub fn force_version(&mut self, version: QuicVersion) {
        self.current_version = Some(version);
        self.negotiation_complete = true;
    }
}

/// Result of version negotiation
#[derive(Debug, Clone)]
pub enum VersionNegotiationResult {
    /// Version was accepted
    Accepted(QuicVersion),
    /// Version was rejected, here are our supported versions
    Rejected {
        supported_versions: Vec<QuicVersion>,
    },
}

impl Default for VersionNegotiationManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_creation() {
        let v1 = QuicVersion::V1;
        assert_eq!(v1.value(), 0x00000001);

        let v2 = QuicVersion::V2;
        assert_eq!(v2.value(), 0x6b3343cf);
    }

    #[test]
    fn test_reserved_version() {
        let reserved = QuicVersion::RESERVED_VN;
        assert!(reserved.is_reserved());

        let v1 = QuicVersion::V1;
        assert!(!v1.is_reserved());
    }

    #[test]
    fn test_version_negotiation_packet() {
        let scid = vec![1, 2, 3, 4];
        let dcid = vec![5, 6, 7, 8];
        let versions = vec![QuicVersion::V1, QuicVersion::V2];

        let packet = VersionNegotiationPacket::new(scid.clone(), dcid.clone(), versions.clone());
        let encoded = packet.encode();
        let decoded = VersionNegotiationPacket::decode(&encoded).unwrap();

        assert_eq!(decoded.scid, scid);
        assert_eq!(decoded.dcid, dcid);
        assert_eq!(decoded.supported_versions, versions);
    }

    #[test]
    fn test_version_negotiation_manager() {
        let mut manager = VersionNegotiationManager::new();

        // Test successful negotiation
        let result = manager.handle_initial_version(QuicVersion::V1).unwrap();
        match result {
            VersionNegotiationResult::Accepted(version) => {
                assert_eq!(version, QuicVersion::V1);
                assert_eq!(manager.current_version(), Some(QuicVersion::V1));
                assert!(manager.is_complete());
            }
            _ => panic!("Expected accepted"),
        }
    }

    #[test]
    fn test_version_rejection() {
        let mut manager = VersionNegotiationManager::with_versions(vec![QuicVersion::V1]);

        // Test rejection of unsupported version
        let result = manager.handle_initial_version(QuicVersion::DRAFT_29).unwrap();
        match result {
            VersionNegotiationResult::Rejected { supported_versions } => {
                assert_eq!(supported_versions, vec![QuicVersion::V1]);
                assert_eq!(manager.current_version(), None);
                assert!(!manager.is_complete());
            }
            _ => panic!("Expected rejected"),
        }
    }
}