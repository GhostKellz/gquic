//! TLS 1.3 integration for QUIC handshake
//! 
//! This module provides TLS 1.3 integration using rustls for proper QUIC handshake
//! according to RFC 9001 (Using TLS to Secure QUIC).

use crate::quic::error::{QuicError, Result};
use bytes::Bytes;
use rustls::{
    ClientConfig, ServerConfig, ClientConnection, ServerConnection,
    RootCertStore,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;
use tracing::{debug, info, warn, error};

/// TLS 1.3 handshake state for QUIC connections
#[derive(Debug, Clone, PartialEq)]
pub enum TlsHandshakeState {
    /// Initial state - no handshake started
    Initial,
    /// Handshake in progress
    InProgress,
    /// Handshake completed successfully
    Established,
    /// Handshake failed
    Failed(String),
}

/// TLS 1.3 handshake manager for QUIC
pub struct QuicTlsHandshake {
    /// Current handshake state
    state: TlsHandshakeState,
    /// TLS connection (client or server)
    connection: TlsConnection,
    /// Server name for client connections
    server_name: Option<String>,
    /// ALPN protocols
    alpn_protocols: Vec<Vec<u8>>,
}

/// TLS connection wrapper for QUIC
pub enum TlsConnection {
    /// Client-side TLS connection
    Client(ClientConnection),
    /// Server-side TLS connection
    Server(ServerConnection),
}

impl QuicTlsHandshake {
    /// Create a new client-side TLS handshake
    pub fn new_client(server_name: &str, alpn_protocols: Vec<Vec<u8>>) -> Result<Self> {
        // Create client config with web PKI roots
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let mut config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        // Set ALPN protocols
        config.alpn_protocols = alpn_protocols.clone();

        // Enable QUIC support
        config.enable_quic();

        // Create client connection
        let client_connection = ClientConnection::new(Arc::new(config), server_name.try_into()
            .map_err(|e| QuicError::Crypto(format!("Invalid server name: {:?}", e)))?)
            .map_err(|e| QuicError::Crypto(format!("Failed to create TLS client connection: {:?}", e)))?;

        Ok(Self {
            state: TlsHandshakeState::Initial,
            connection: TlsConnection::Client(client_connection),
            server_name: Some(server_name.to_string()),
            alpn_protocols,
        })
    }

    /// Create a new server-side TLS handshake
    pub fn new_server(cert_chain: Vec<Certificate>, private_key: PrivateKey, alpn_protocols: Vec<Vec<u8>>) -> Result<Self> {
        // Create server config
        let mut config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .map_err(|e| QuicError::Crypto(format!("Failed to create server config: {:?}", e)))?;

        // Set ALPN protocols
        config.alpn_protocols = alpn_protocols.clone();

        // Enable QUIC support
        config.enable_quic();

        // Create server connection
        let server_connection = ServerConnection::new(Arc::new(config))
            .map_err(|e| QuicError::Crypto(format!("Failed to create TLS server connection: {:?}", e)))?;

        Ok(Self {
            state: TlsHandshakeState::Initial,
            connection: TlsConnection::Server(server_connection),
            server_name: None,
            alpn_protocols,
        })
    }

    /// Get the current handshake state
    pub fn state(&self) -> &TlsHandshakeState {
        &self.state
    }

    /// Check if the handshake is complete
    pub fn is_established(&self) -> bool {
        matches!(self.state, TlsHandshakeState::Established)
    }

    /// Get the negotiated ALPN protocol
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        match &self.connection {
            TlsConnection::Client(conn) => conn.alpn_protocol(),
            TlsConnection::Server(conn) => conn.alpn_protocol(),
        }
    }

    /// Start the TLS handshake
    pub fn start_handshake(&mut self) -> Result<Option<Bytes>> {
        self.state = TlsHandshakeState::InProgress;
        
        match &mut self.connection {
            TlsConnection::Client(conn) => {
                // For client, we need to complete the handshake
                match conn.quic_transport_parameters() {
                    Some(_) => {
                        // Handshake data is available
                        let handshake_data = conn.quic_write_handshake(&mut Vec::new())
                            .map_err(|e| QuicError::Crypto(format!("Failed to write handshake: {:?}", e)))?;
                        
                        if !handshake_data.is_empty() {
                            debug!("Client handshake data ready: {} bytes", handshake_data.len());
                            Ok(Some(Bytes::from(handshake_data)))
                        } else {
                            Ok(None)
                        }
                    }
                    None => {
                        // No handshake data yet
                        Ok(None)
                    }
                }
            }
            TlsConnection::Server(conn) => {
                // For server, we wait for client data
                Ok(None)
            }
        }
    }

    /// Process incoming handshake data
    pub fn process_handshake_data(&mut self, data: &[u8]) -> Result<Option<Bytes>> {
        match &mut self.connection {
            TlsConnection::Client(conn) => {
                // Process server response
                conn.quic_read_handshake(data)
                    .map_err(|e| QuicError::Crypto(format!("Failed to read handshake: {:?}", e)))?;

                // Check if handshake is complete
                if conn.is_handshaking() {
                    // Still handshaking, get next data to send
                    let handshake_data = conn.quic_write_handshake(&mut Vec::new())
                        .map_err(|e| QuicError::Crypto(format!("Failed to write handshake: {:?}", e)))?;
                    
                    if !handshake_data.is_empty() {
                        debug!("Client handshake continues: {} bytes", handshake_data.len());
                        Ok(Some(Bytes::from(handshake_data)))
                    } else {
                        Ok(None)
                    }
                } else {
                    // Handshake complete
                    self.state = TlsHandshakeState::Established;
                    info!("TLS handshake established (client)");
                    Ok(None)
                }
            }
            TlsConnection::Server(conn) => {
                // Process client data
                conn.quic_read_handshake(data)
                    .map_err(|e| QuicError::Crypto(format!("Failed to read handshake: {:?}", e)))?;

                // Generate server response
                let handshake_data = conn.quic_write_handshake(&mut Vec::new())
                    .map_err(|e| QuicError::Crypto(format!("Failed to write handshake: {:?}", e)))?;

                // Check if handshake is complete
                if !conn.is_handshaking() {
                    self.state = TlsHandshakeState::Established;
                    info!("TLS handshake established (server)");
                }

                if !handshake_data.is_empty() {
                    debug!("Server handshake data: {} bytes", handshake_data.len());
                    Ok(Some(Bytes::from(handshake_data)))
                } else {
                    Ok(None)
                }
            }
        }
    }

    /// Get transport parameters for QUIC
    pub fn transport_parameters(&self) -> Option<&[u8]> {
        match &self.connection {
            TlsConnection::Client(conn) => conn.quic_transport_parameters(),
            TlsConnection::Server(conn) => conn.quic_transport_parameters(),
        }
    }

    /// Set transport parameters for QUIC
    pub fn set_transport_parameters(&mut self, params: &[u8]) -> Result<()> {
        match &mut self.connection {
            TlsConnection::Client(conn) => {
                conn.quic_set_transport_parameters(params)
                    .map_err(|e| QuicError::Crypto(format!("Failed to set transport parameters: {:?}", e)))?;
            }
            TlsConnection::Server(conn) => {
                conn.quic_set_transport_parameters(params)
                    .map_err(|e| QuicError::Crypto(format!("Failed to set transport parameters: {:?}", e)))?;
            }
        }
        Ok(())
    }

    /// Get the TLS export keying material for QUIC keys
    pub fn export_keying_material(&self, label: &[u8], context: &[u8], key_len: usize) -> Result<Vec<u8>> {
        let mut output = vec![0u8; key_len];
        
        match &self.connection {
            TlsConnection::Client(conn) => {
                conn.export_keying_material(&mut output, label, context)
                    .map_err(|e| QuicError::Crypto(format!("Failed to export keying material: {:?}", e)))?;
            }
            TlsConnection::Server(conn) => {
                conn.export_keying_material(&mut output, label, context)
                    .map_err(|e| QuicError::Crypto(format!("Failed to export keying material: {:?}", e)))?;
            }
        }
        
        Ok(output)
    }

    /// Get the TLS cipher suite
    pub fn cipher_suite(&self) -> Option<rustls::SupportedCipherSuite> {
        match &self.connection {
            TlsConnection::Client(conn) => conn.negotiated_cipher_suite(),
            TlsConnection::Server(conn) => conn.negotiated_cipher_suite(),
        }
    }

    /// Handle TLS errors and update state
    pub fn handle_error(&mut self, error: &str) {
        error!("TLS handshake error: {}", error);
        self.state = TlsHandshakeState::Failed(error.to_string());
    }
}

/// Helper function to create default ALPN protocols for gRPC-over-QUIC
pub fn grpc_alpn_protocols() -> Vec<Vec<u8>> {
    vec![
        b"h3".to_vec(),      // HTTP/3
        b"grpc".to_vec(),    // gRPC-over-QUIC
    ]
}

/// Helper function to create default ALPN protocols for HTTP/3
pub fn http3_alpn_protocols() -> Vec<Vec<u8>> {
    vec![
        b"h3".to_vec(),      // HTTP/3
        b"h3-29".to_vec(),   // HTTP/3 draft-29
        b"h3-27".to_vec(),   // HTTP/3 draft-27
    ]
}

/// Helper function to load certificates from PEM file
pub fn load_certs(filename: &str) -> Result<Vec<CertificateDer<'static>>> {
    let certfile = std::fs::File::open(filename)
        .map_err(|e| QuicError::Config(format!("Failed to open cert file: {}", e)))?;
    let mut reader = std::io::BufReader::new(certfile);
    
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    let certs = certs.map_err(|e| QuicError::Config(format!("Failed to parse certificates: {}", e)))?;
    
    Ok(certs)
}

/// Helper function to load private key from PEM file
pub fn load_private_key(filename: &str) -> Result<PrivateKeyDer<'static>> {
    let keyfile = std::fs::File::open(filename)
        .map_err(|e| QuicError::Config(format!("Failed to open key file: {}", e)))?;
    let mut reader = std::io::BufReader::new(keyfile);
    
    let keys: Result<Vec<_>, _> = rustls_pemfile::pkcs8_private_keys(&mut reader).collect();
    let keys = keys.map_err(|e| QuicError::Config(format!("Failed to parse private key: {}", e)))?;
    
    if keys.is_empty() {
        return Err(QuicError::Config("No private key found".to_string()));
    }
    
    Ok(PrivateKeyDer::Pkcs8(keys[0].clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alpn_protocols() {
        let grpc_protocols = grpc_alpn_protocols();
        assert_eq!(grpc_protocols.len(), 2);
        assert_eq!(grpc_protocols[0], b"h3");
        assert_eq!(grpc_protocols[1], b"grpc");

        let http3_protocols = http3_alpn_protocols();
        assert_eq!(http3_protocols.len(), 3);
        assert_eq!(http3_protocols[0], b"h3");
    }

    #[test]
    fn test_handshake_state() {
        let state = TlsHandshakeState::Initial;
        assert_eq!(state, TlsHandshakeState::Initial);

        let state = TlsHandshakeState::Failed("test error".to_string());
        assert!(matches!(state, TlsHandshakeState::Failed(_)));
    }
}