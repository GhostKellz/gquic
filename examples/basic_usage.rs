use std::net::SocketAddr;
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tracing::{info, error};

use gquic::prelude::*;
use gquic::crypto::{default_backend, QuicCrypto};
use gquic::security::{DdosProtection, DdosConfig};
use gquic::quic::udp_mux::UdpMultiplexer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::init();
    
    info!("🚀 Starting GQUIC Basic Usage Example");
    
    // Set up crypto backend
    let crypto_backend = default_backend();
    let quic_crypto = Arc::new(QuicCrypto::new(crypto_backend));
    
    // Set up DDoS protection
    let ddos_config = DdosConfig::default();
    let ddos_protection = Arc::new(DdosProtection::new(ddos_config));
    
    // Create UDP multiplexer for server
    let server_addr: SocketAddr = "127.0.0.1:5555".parse()?;
    let server_mux = UdpMultiplexer::new(server_addr).await?;
    
    info!("🌐 Server bound to {}", server_mux.local_addr());
    
    // Spawn server task
    let server_ddos = Arc::clone(&ddos_protection);
    let server_task = tokio::spawn(async move {
        info!("📡 Starting server UDP multiplexer");
        
        // In a real application, you would:
        // 1. Accept incoming connections
        // 2. Perform handshake
        // 3. Set up crypto
        // 4. Handle streams
        
        loop {
            // Cleanup old DDoS entries periodically
            server_ddos.cleanup_old_entries().await;
            sleep(Duration::from_secs(60)).await;
        }
    });
    
    // Create client endpoint
    let client_config = EndpointConfig {
        bind_address: "127.0.0.1:0".parse()?,
        max_idle_timeout: Duration::from_secs(30),
        max_concurrent_streams: 100,
        keep_alive_interval: Some(Duration::from_secs(10)),
        enable_0rtt: false,
    };
    
    let client_endpoint = Endpoint::client(client_config).await?;
    info!("👤 Client endpoint created at {}", client_endpoint.local_addr());
    
    // Connect to server (simulated)
    info!("🔗 Connecting to server...");
    
    // In a real implementation, this would:
    // 1. Send Initial packet
    // 2. Perform TLS handshake
    // 3. Exchange transport parameters
    // 4. Establish 1-RTT keys
    
    // For demonstration, we'll create a mock connection
    let connection_id = gquic::quic::ConnectionId::new();
    let connection = gquic::quic::Connection::new(
        connection_id.clone(),
        server_addr,
        Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await?),
        true, // is_client
    );
    
    // Initialize crypto for the connection
    connection.initialize_crypto(quic_crypto).await?;
    info!("🔐 Crypto initialized for connection {}", connection_id);
    
    // Demonstrate stream creation
    info!("📨 Creating bidirectional stream...");
    
    // In a real implementation, you would:
    // 1. Open streams on the connection
    // 2. Send/receive data
    // 3. Handle flow control
    // 4. Process QUIC frames
    
    info!("✅ GQUIC example completed successfully!");
    info!("📊 Connection stats: {:?}", connection.stats().await);
    
    // Cleanup
    server_task.abort();
    
    Ok(())
}

/// Demonstrate crypto operations
async fn demonstrate_crypto() -> Result<(), Box<dyn std::error::Error>> {
    use gquic::crypto::{KeyType, RustlsBackend, CryptoBackend};
    
    info!("🔑 Demonstrating crypto operations...");
    
    let backend = RustlsBackend::new();
    
    // Generate a keypair
    let keypair = backend.generate_keypair(KeyType::Ed25519)?;
    info!("✅ Generated Ed25519 keypair");
    
    // Sign and verify data
    let data = b"Hello, GQUIC!";
    let signature = backend.sign(&keypair.private_key, data)?;
    let is_valid = backend.verify(&keypair.public_key, data, &signature)?;
    
    info!("✅ Signature verification: {}", is_valid);
    
    // Key derivation (HKDF)
    let secret = b"secret key material";
    let salt = b"salt";
    let info = b"quic key derivation";
    let derived_key = backend.derive_key(secret, salt, info, 32)?;
    
    info!("✅ Derived {} byte key", derived_key.len());
    
    // AEAD encryption/decryption
    let key = &derived_key[..16];
    let nonce = &derived_key[16..28];
    let aad = b"associated data";
    let plaintext = b"sensitive data to encrypt";
    
    let ciphertext = backend.encrypt_aead(key, nonce, aad, plaintext)?;
    let decrypted = backend.decrypt_aead(key, nonce, aad, &ciphertext)?;
    
    info!("✅ AEAD encryption/decryption successful");
    assert_eq!(plaintext, &decrypted[..]);
    
    Ok(())
}

/// Demonstrate DDoS protection
async fn demonstrate_ddos_protection() -> Result<(), Box<dyn std::error::Error>> {
    use std::net::IpAddr;
    
    info!("🛡️ Demonstrating DDoS protection...");
    
    let ddos = DdosProtection::new(DdosConfig::default());
    let test_addr: SocketAddr = "192.168.1.100:12345".parse()?;
    
    // Simulate normal traffic
    for i in 0..5 {
        match ddos.check_connection_allowed(test_addr).await {
            Ok(()) => info!("✅ Connection {} allowed", i + 1),
            Err(e) => error!("❌ Connection {} blocked: {}", i + 1, e),
        }
    }
    
    // Simulate burst traffic that should trigger protection
    for i in 0..60 {
        let result = ddos.check_connection_allowed(test_addr).await;
        if result.is_err() {
            info!("🚫 DDoS protection triggered at connection {}", i + 1);
            break;
        }
    }
    
    let stats = ddos.get_stats().await;
    info!("📊 DDoS stats: {:?}", stats);
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_basic_crypto() {
        demonstrate_crypto().await.expect("Crypto demo failed");
    }
    
    #[tokio::test]
    async fn test_ddos_protection() {
        demonstrate_ddos_protection().await.expect("DDoS demo failed");
    }
}