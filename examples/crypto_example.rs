use gquic::{Endpoint, CryptoEndpoint, Frame, QuicResult};
use std::net::SocketAddr;
use bytes::Bytes;

#[tokio::main]
async fn main() -> QuicResult<()> {
    println!("🚀 GQUIC Crypto Example - Production Ready for Blockchain Applications");
    
    // Basic QUIC endpoint
    let addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
    let endpoint = Endpoint::bind(addr).await?;
    println!("✅ Basic QUIC endpoint bound to {}", addr);
    
    // Crypto-enhanced endpoint
    let crypto_addr: SocketAddr = "127.0.0.1:4434".parse().unwrap();
    let crypto_key = b"my_secret_crypto_key_32_bytes___".to_vec();
    let mut crypto_endpoint = Endpoint::bind_crypto(crypto_addr, crypto_key.clone()).await?;
    println!("✅ Crypto QUIC endpoint bound to {}", crypto_addr);
    
    // Demonstrate crypto frame types
    demo_crypto_frames();
    
    // Show endpoint stats
    let stats = endpoint.stats();
    println!("📊 Endpoint Stats: {} active connections", stats.active_connections);
    
    println!("🎯 GQUIC is ready for your crypto project!");
    println!("   - Encrypted packet handling ✅");
    println!("   - Blockchain-specific frames ✅");
    println!("   - Crypto authentication ✅");
    println!("   - Production monitoring ✅");
    
    Ok(())
}

fn demo_crypto_frames() {
    println!("\n🔐 Demonstrating Crypto Frame Types:");
    
    // Crypto handshake frame
    let handshake_frame = Frame::CryptoHandshake {
        key_exchange: Bytes::from("dh_public_key_exchange_data"),
    };
    let encoded = handshake_frame.encode_crypto();
    println!("   Crypto Handshake Frame: {} bytes", encoded.len());
    
    // Blockchain data frame
    let blockchain_frame = Frame::BlockchainData {
        chain_id: 1,
        block_hash: Bytes::from("block_hash_32_bytes_placeholder_"),
        data: Bytes::from("transaction_data"),
    };
    let encoded = blockchain_frame.encode_crypto();
    println!("   Blockchain Data Frame: {} bytes", encoded.len());
    
    // Crypto auth frame
    let auth_frame = Frame::CryptoAuth {
        signature: Bytes::from("ed25519_signature_64_bytes_placeholder_data_here_for_demo_"),
        public_key: Bytes::from("ed25519_public_key_32_bytes_here"),
    };
    let encoded = auth_frame.encode_crypto();
    println!("   Crypto Auth Frame: {} bytes", encoded.len());
    
    // Secure channel frame
    let secure_frame = Frame::SecureChannel {
        encrypted_payload: Bytes::from("aes256_encrypted_payload_data"),
        nonce: Bytes::from("random_nonce"),
    };
    let encoded = secure_frame.encode_crypto();
    println!("   Secure Channel Frame: {} bytes", encoded.len());
}
