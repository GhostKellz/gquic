use anyhow::Result;
use quinn::TransportConfig;
use rustls::{Certificate, PrivateKey, ServerConfig as RustlsServerConfig};
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct QuicServerConfig {
    pub bind_addr: SocketAddr,
    pub tls_config: RustlsServerConfig,
    pub transport_config: TransportConfig,
    pub alpn_protocols: Vec<Vec<u8>>,
}

impl QuicServerConfig {
    pub fn builder() -> QuicServerConfigBuilder {
        QuicServerConfigBuilder::new()
    }
}

pub struct QuicServerConfigBuilder {
    bind_addr: Option<SocketAddr>,
    cert_chain: Option<Vec<Certificate>>,
    private_key: Option<PrivateKey>,
    alpn_protocols: Vec<Vec<u8>>,
    transport_config: TransportConfig,
}

impl QuicServerConfigBuilder {
    pub fn new() -> Self {
        let mut transport_config = TransportConfig::default();
        
        // Optimize for GhostChain use case
        transport_config.max_concurrent_bidi_streams(100_u32.into());
        transport_config.max_concurrent_uni_streams(100_u32.into());
        transport_config.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
        transport_config.keep_alive_interval(Some(Duration::from_secs(10)));
        
        Self {
            bind_addr: None,
            cert_chain: None,
            private_key: None,
            alpn_protocols: vec![b"h3".to_vec(), b"gquic".to_vec()],
            transport_config,
        }
    }

    pub fn bind(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = Some(addr);
        self
    }

    pub fn with_tls_files(mut self, cert_path: &str, key_path: &str) -> Result<Self> {
        let cert_chain = Self::load_certs(cert_path)?;
        let private_key = Self::load_private_key(key_path)?;
        
        self.cert_chain = Some(cert_chain);
        self.private_key = Some(private_key);
        Ok(self)
    }

    pub fn with_self_signed_cert(mut self) -> Result<Self> {
        let (cert_chain, private_key) = Self::generate_self_signed_cert()?;
        
        self.cert_chain = Some(cert_chain);
        self.private_key = Some(private_key);
        Ok(self)
    }

    pub fn with_alpn(mut self, protocol: &str) -> Self {
        self.alpn_protocols.push(protocol.as_bytes().to_vec());
        self
    }

    pub fn max_concurrent_bidi_streams(mut self, count: u32) -> Self {
        self.transport_config.max_concurrent_bidi_streams(count.into());
        self
    }

    pub fn max_concurrent_uni_streams(mut self, count: u32) -> Self {
        self.transport_config.max_concurrent_uni_streams(count.into());
        self
    }

    pub fn max_idle_timeout(mut self, timeout: Duration) -> Self {
        self.transport_config.max_idle_timeout(Some(timeout.try_into().unwrap()));
        self
    }

    pub fn keep_alive_interval(mut self, interval: Duration) -> Self {
        self.transport_config.keep_alive_interval(Some(interval));
        self
    }

    pub fn build(self) -> Result<QuicServerConfig> {
        let bind_addr = self.bind_addr.unwrap_or_else(|| "0.0.0.0:443".parse().unwrap());
        
        let cert_chain = self.cert_chain.ok_or_else(|| {
            anyhow::anyhow!("TLS certificate required")
        })?;
        
        let private_key = self.private_key.ok_or_else(|| {
            anyhow::anyhow!("TLS private key required")
        })?;

        let tls_config = RustlsServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)?;

        Ok(QuicServerConfig {
            bind_addr,
            tls_config,
            transport_config: self.transport_config,
            alpn_protocols: self.alpn_protocols,
        })
    }

    fn load_certs(path: &str) -> Result<Vec<Certificate>> {
        let cert_data = fs::read(path)?;
        let certs = rustls_pemfile::certs(&mut cert_data.as_slice())?
            .into_iter()
            .map(Certificate)
            .collect();
        Ok(certs)
    }

    fn load_private_key(path: &str) -> Result<PrivateKey> {
        let key_data = fs::read(path)?;
        let mut key_reader = key_data.as_slice();
        
        // Try different key formats
        if let Ok(keys) = rustls_pemfile::pkcs8_private_keys(&mut key_reader) {
            if !keys.is_empty() {
                return Ok(PrivateKey(keys[0].clone()));
            }
        }

        key_reader = key_data.as_slice();
        if let Ok(keys) = rustls_pemfile::rsa_private_keys(&mut key_reader) {
            if !keys.is_empty() {
                return Ok(PrivateKey(keys[0].clone()));
            }
        }

        Err(anyhow::anyhow!("No valid private key found"))
    }

    fn generate_self_signed_cert() -> Result<(Vec<Certificate>, PrivateKey)> {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let cert_der = cert.serialize_der()?;
        let private_key_der = cert.serialize_private_key_der();

        Ok((
            vec![Certificate(cert_der)],
            PrivateKey(private_key_der),
        ))
    }
}

impl Default for QuicServerConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}