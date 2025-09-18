//! QUIC connection handshake implementation with TLS 1.3 integration

use crate::crypto::{CryptoBackend, KeyType, KeyPair, PrivateKey, PublicKey, Signature, quic_crypto::{QuicCrypto, EncryptionLevel, TransportParameters}, tls::{HandshakeState as TlsHandshakeState, TlsConfig}, default_crypto_backend};
use crate::quic::{connection::ConnectionId, frame::Frame, packet::PacketHeader};
use crate::protection::PacketProtection;
use anyhow::{Result, anyhow};
use bytes::Bytes;
use std::sync::Arc;
use std::collections::HashMap;

/// QUIC handshake state aligned with TLS 1.3
#[derive(Debug, Clone, PartialEq)]
pub enum HandshakeState {
    /// Initial state - no handshake started
    Initial,
    /// Waiting for Initial packet (server) or sending Initial (client)
    WaitInitial,
    /// Processing TLS ClientHello/ServerHello
    WaitServerHello,
    /// Processing encrypted handshake messages
    WaitHandshake,
    /// Handshake complete, connection established
    Complete,
    /// Handshake failed
    Failed(String),
}

/// QUIC connection handshake manager with TLS 1.3 integration
pub struct QuicHandshake {
    /// Current handshake state
    state: HandshakeState,
    /// Whether this is a client or server handshake
    is_server: bool,
    /// Connection ID for this handshake
    connection_id: ConnectionId,
    /// Crypto backend for operations
    crypto: QuicCrypto,
    /// TLS 1.3 configuration
    tls_config: TlsConfig,
    /// Packet protection for different encryption levels
    packet_protection: PacketProtection,
    /// Transport parameters to send/received
    local_transport_params: TransportParameters,
    peer_transport_params: Option<TransportParameters>,
    /// Crypto frame buffers by encryption level
    crypto_buffers: HashMap<EncryptionLevel, Vec<u8>>,
    /// Next expected offset for crypto frames
    crypto_offsets: HashMap<EncryptionLevel, u64>,
}

impl std::fmt::Debug for QuicHandshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicHandshake")
            .field("state", &self.state)
            .field("is_server", &self.is_server)
            .field("connection_id", &self.connection_id)
            .field("peer_transport_params", &self.peer_transport_params.is_some())
            .finish()
    }
}

impl QuicHandshake {
    /// Create a new client handshake
    pub fn new_client(connection_id: ConnectionId, server_name: String) -> Result<Self> {
        let backend = default_crypto_backend();
        let crypto = QuicCrypto::new(backend.clone());
        let mut packet_protection = PacketProtection::new(backend);

        // Initialize keys for Initial encryption level
        packet_protection.initialize_keys(connection_id.as_bytes(), false)?;

        let mut tls_config = TlsConfig::default();
        tls_config.server_name = Some(server_name);

        Ok(Self {
            state: HandshakeState::Initial,
            is_server: false,
            connection_id,
            crypto,
            tls_config,
            packet_protection,
            local_transport_params: TransportParameters::default(),
            peer_transport_params: None,
            crypto_buffers: HashMap::new(),
            crypto_offsets: HashMap::new(),
        })
    }

    /// Create a new server handshake
    pub fn new_server(connection_id: ConnectionId, private_key: PrivateKey, cert_chain: Vec<Vec<u8>>) -> Result<Self> {
        let backend = default_crypto_backend();
        let crypto = QuicCrypto::new(backend.clone());
        let mut packet_protection = PacketProtection::new(backend);

        // Initialize keys for Initial encryption level
        packet_protection.initialize_keys(connection_id.as_bytes(), true)?;

        let mut tls_config = TlsConfig::default();
        tls_config.private_key = Some(private_key);
        tls_config.certificate_chain = cert_chain;

        Ok(Self {
            state: HandshakeState::WaitInitial,
            is_server: true,
            connection_id,
            crypto,
            tls_config,
            packet_protection,
            local_transport_params: TransportParameters::default(),
            peer_transport_params: None,
            crypto_buffers: HashMap::new(),
            crypto_offsets: HashMap::new(),
        })
    }
    
    /// Start client handshake by generating ClientHello
    pub fn start_client_handshake(&mut self) -> Result<Vec<Frame>> {
        if self.state != HandshakeState::Initial {
            return Err(anyhow!("Handshake already started"));
        }

        self.state = HandshakeState::WaitServerHello;

        // Generate TLS 1.3 ClientHello with QUIC transport parameters
        let client_hello = self.generate_client_hello()?;

        Ok(vec![Frame::Crypto {
            offset: 0,
            data: Bytes::from(client_hello),
        }])
    }

    /// Process incoming crypto frame data
    pub fn process_crypto_frame(&mut self, level: EncryptionLevel, frame: Frame) -> Result<Vec<Frame>> {
        match frame {
            Frame::Crypto { offset, data } => {
                // Buffer crypto data in order
                self.buffer_crypto_data(level, offset, data)?;

                // Try to process complete handshake messages
                self.process_buffered_crypto_data(level)
            }
            _ => Err(anyhow!("Expected Crypto frame")),
        }
    }

    /// Buffer crypto frame data and check for completeness
    fn buffer_crypto_data(&mut self, level: EncryptionLevel, offset: u64, data: Bytes) -> Result<()> {
        let expected_offset = self.crypto_offsets.get(&level).copied().unwrap_or(0);

        if offset == expected_offset {
            // Data is in order, append to buffer
            let buffer = self.crypto_buffers.entry(level).or_insert_with(Vec::new);
            buffer.extend_from_slice(&data);
            self.crypto_offsets.insert(level, offset + data.len() as u64);
        } else if offset < expected_offset {
            // Duplicate or old data, ignore
            return Ok(());
        } else {
            // Future data, buffer but don't process yet
            // TODO: Implement proper out-of-order buffering
            return Err(anyhow!("Out-of-order crypto data not implemented"));
        }

        Ok(())
    }

    /// Process buffered crypto data for complete TLS messages
    fn process_buffered_crypto_data(&mut self, level: EncryptionLevel) -> Result<Vec<Frame>> {
        let buffer = self.crypto_buffers.get(&level).unwrap_or(&Vec::new()).clone();

        match level {
            EncryptionLevel::Initial => {
                if self.is_server {
                    self.process_client_hello(&buffer)
                } else {
                    self.process_server_hello(&buffer)
                }
            }
            EncryptionLevel::Handshake => {
                self.process_handshake_messages(&buffer)
            }
            EncryptionLevel::OneRtt => {
                // Should not have crypto frames at 1-RTT level
                Err(anyhow!("Unexpected crypto frame at 1-RTT level"))
            }
        }
    }

    /// Generate TLS 1.3 ClientHello with QUIC transport parameters
    fn generate_client_hello(&self) -> Result<Vec<u8>> {
        // Simplified ClientHello generation
        let mut client_hello = Vec::new();

        // TLS handshake message header
        client_hello.push(0x01); // ClientHello
        client_hello.extend_from_slice(&[0x00, 0x00, 0x00]); // Length placeholder

        // TLS version (1.2 for compatibility, actual version negotiated in extensions)
        client_hello.extend_from_slice(&[0x03, 0x03]);

        // Random (32 bytes)
        client_hello.extend_from_slice(&[0; 32]); // TODO: Use actual random

        // Session ID (empty for QUIC)
        client_hello.push(0x00);

        // Cipher suites
        client_hello.extend_from_slice(&[0x00, 0x02]); // Length
        client_hello.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256

        // Compression methods
        client_hello.push(0x01); // Length
        client_hello.push(0x00); // null compression

        // Extensions
        let mut extensions = Vec::new();

        // Add QUIC transport parameters extension
        self.add_transport_parameters_extension(&mut extensions)?;

        // Add supported versions extension (TLS 1.3)
        extensions.extend_from_slice(&[0x00, 0x2b]); // Extension type
        extensions.extend_from_slice(&[0x00, 0x03]); // Length
        extensions.push(0x02); // Version list length
        extensions.extend_from_slice(&[0x03, 0x04]); // TLS 1.3

        // Add ALPN extension for HTTP/3
        if let alpn_protocols = &self.tls_config.alpn_protocols {
            if !alpn_protocols.is_empty() {
                extensions.extend_from_slice(&[0x00, 0x10]); // ALPN extension type
                let alpn_data_len = alpn_protocols.iter().map(|p| p.len() + 1).sum::<usize>();
                extensions.extend_from_slice(&(alpn_data_len as u16 + 2).to_be_bytes());
                extensions.extend_from_slice(&(alpn_data_len as u16).to_be_bytes());
                for protocol in alpn_protocols {
                    extensions.push(protocol.len() as u8);
                    extensions.extend_from_slice(protocol);
                }
            }
        }

        // Update extensions length
        let extensions_len = extensions.len() as u16;
        client_hello.extend_from_slice(&extensions_len.to_be_bytes());
        client_hello.extend_from_slice(&extensions);

        // Update message length
        let message_len = (client_hello.len() - 4) as u32;
        client_hello[1..4].copy_from_slice(&message_len.to_be_bytes()[1..]);

        Ok(client_hello)
    }

    /// Add QUIC transport parameters extension
    fn add_transport_parameters_extension(&self, extensions: &mut Vec<u8>) -> Result<()> {
        extensions.extend_from_slice(&[0xff, 0x01]); // QUIC transport parameters extension type

        let mut params = Vec::new();

        // Encode transport parameters
        self.encode_transport_parameter(&mut params, 0x00, &self.local_transport_params.max_idle_timeout.to_be_bytes()[4..])?; // max_idle_timeout
        self.encode_transport_parameter(&mut params, 0x01, &self.local_transport_params.max_udp_payload_size.to_be_bytes()[2..])?; // max_udp_payload_size
        self.encode_transport_parameter(&mut params, 0x04, &self.local_transport_params.initial_max_data.to_be_bytes())?; // initial_max_data

        let params_len = params.len() as u16;
        extensions.extend_from_slice(&params_len.to_be_bytes());
        extensions.extend_from_slice(&params);

        Ok(())
    }

    /// Encode a single transport parameter
    fn encode_transport_parameter(&self, buffer: &mut Vec<u8>, param_id: u16, value: &[u8]) -> Result<()> {
        // Parameter ID (varint)
        self.encode_varint(buffer, param_id as u64);
        // Parameter length (varint)
        self.encode_varint(buffer, value.len() as u64);
        // Parameter value
        buffer.extend_from_slice(value);
        Ok(())
    }

    /// Encode varint
    fn encode_varint(&self, buffer: &mut Vec<u8>, mut value: u64) {
        if value < 64 {
            buffer.push(value as u8);
        } else if value < 16384 {
            buffer.extend_from_slice(&(0x4000 | value as u16).to_be_bytes());
        } else if value < 1073741824 {
            buffer.extend_from_slice(&(0x80000000 | value as u32).to_be_bytes());
        } else {
            buffer.extend_from_slice(&(0xc000000000000000 | value).to_be_bytes());
        }
    }

    /// Process ClientHello (server side)
    fn process_client_hello(&mut self, _data: &[u8]) -> Result<Vec<Frame>> {
        if !self.is_server || self.state != HandshakeState::WaitInitial {
            return Err(anyhow!("Invalid state for ClientHello"));
        }

        self.state = HandshakeState::WaitHandshake;

        // Generate ServerHello
        let server_hello = self.generate_server_hello()?;

        Ok(vec![Frame::Crypto {
            offset: 0,
            data: Bytes::from(server_hello),
        }])
    }

    /// Process ServerHello (client side)
    fn process_server_hello(&mut self, _data: &[u8]) -> Result<Vec<Frame>> {
        if self.is_server || self.state != HandshakeState::WaitServerHello {
            return Err(anyhow!("Invalid state for ServerHello"));
        }

        self.state = HandshakeState::WaitHandshake;

        // TODO: Parse ServerHello and extract transport parameters
        // TODO: Derive handshake keys and update packet protection

        Ok(vec![])
    }

    /// Generate ServerHello
    fn generate_server_hello(&self) -> Result<Vec<u8>> {
        // Simplified ServerHello - in production this would be much more complex
        let mut server_hello = Vec::new();

        server_hello.push(0x02); // ServerHello
        server_hello.extend_from_slice(&[0x00, 0x00, 0x4a]); // Length

        server_hello.extend_from_slice(&[0x03, 0x03]); // TLS version
        server_hello.extend_from_slice(&[0; 32]); // Random

        server_hello.push(0x00); // Session ID length

        server_hello.extend_from_slice(&[0x13, 0x01]); // Cipher suite

        server_hello.push(0x00); // Compression method

        // Extensions (minimal)
        server_hello.extend_from_slice(&[0x00, 0x0e]); // Extensions length

        // Supported versions extension
        server_hello.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);

        // Key share extension (placeholder)
        server_hello.extend_from_slice(&[0x00, 0x33, 0x00, 0x02, 0x00, 0x00]);

        Ok(server_hello)
    }

    /// Process handshake messages (Certificate, CertificateVerify, Finished)
    fn process_handshake_messages(&mut self, _data: &[u8]) -> Result<Vec<Frame>> {
        if self.state != HandshakeState::WaitHandshake {
            return Err(anyhow!("Invalid state for handshake messages"));
        }

        // TODO: Process Certificate, CertificateVerify, Finished messages
        // TODO: Derive application keys and install them

        self.state = HandshakeState::Complete;

        // Send HandshakeDone frame if server
        if self.is_server {
            Ok(vec![Frame::HandshakeDone])
        } else {
            Ok(vec![])
        }
    }

    /// Check if handshake is complete
    pub fn is_complete(&self) -> bool {
        matches!(self.state, HandshakeState::Complete)
    }

    /// Get current handshake state
    pub fn state(&self) -> &HandshakeState {
        &self.state
    }

    /// Get packet protection (for encrypting/decrypting packets)
    pub fn packet_protection(&self) -> &PacketProtection {
        &self.packet_protection
    }

    /// Get mutable packet protection
    pub fn packet_protection_mut(&mut self) -> &mut PacketProtection {
        &mut self.packet_protection
    }

    /// Get peer transport parameters
    pub fn peer_transport_params(&self) -> Option<&TransportParameters> {
        self.peer_transport_params.as_ref()
    }

    /// Get local transport parameters
    pub fn local_transport_params(&self) -> &TransportParameters {
        &self.local_transport_params
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_handshake_start() {
        let connection_id = ConnectionId::new(b"test_conn_id");
        let mut handshake = QuicHandshake::new_client(connection_id, "example.com".to_string()).unwrap();

        let frames = handshake.start_client_handshake().unwrap();
        assert_eq!(frames.len(), 1);

        match &frames[0] {
            Frame::Crypto { offset, data } => {
                assert_eq!(*offset, 0);
                assert!(!data.is_empty());
            }
            _ => panic!("Expected Crypto frame"),
        }

        assert_eq!(handshake.state(), &HandshakeState::WaitServerHello);
    }

    #[test]
    fn test_server_handshake_creation() {
        let connection_id = ConnectionId::new(b"test_conn_id");
        let private_key = PrivateKey {
            data: vec![0; 32],
            key_type: KeyType::Ed25519,
        };
        let cert_chain = vec![vec![0; 100]]; // Dummy certificate

        let handshake = QuicHandshake::new_server(connection_id, private_key, cert_chain).unwrap();
        assert_eq!(handshake.state(), &HandshakeState::WaitInitial);
        assert!(handshake.is_server);
    }
}
