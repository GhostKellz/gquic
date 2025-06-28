use rustls::RootCertStore;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicClientConfig {
    pub server_name: String,
    pub alpn_protocols: Vec<Vec<u8>>,
    pub root_certs: Arc<RootCertStore>,
    pub max_idle_timeout: Option<u64>,
    pub max_bi_streams: Option<u32>,
    pub max_uni_streams: Option<u32>,
    pub keep_alive_interval: Option<u64>,
}

impl Default for QuicClientConfig {
    fn default() -> Self {
        let mut root_certs = RootCertStore::empty();
        root_certs.add_server_trust_anchors(
            webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
                rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )
            }),
        );

        Self {
            server_name: "localhost".to_string(),
            alpn_protocols: vec![b"h3".to_vec()],
            root_certs: Arc::new(root_certs),
            max_idle_timeout: Some(30_000),
            max_bi_streams: Some(100),
            max_uni_streams: Some(100),
            keep_alive_interval: Some(10_000),
        }
    }
}