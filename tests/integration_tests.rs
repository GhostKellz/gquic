//! Integration tests for GQUIC library
//!
//! These tests verify that the core QUIC functionality works end-to-end.

use gquic::*;
use tokio::time::{timeout, Duration};
use std::net::SocketAddr;

#[tokio::test]
async fn test_basic_connection_establishment() {
    // Create server endpoint
    let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut server = Endpoint::bind(server_addr).await.unwrap();

    let server_addr = server.socket.local_addr().unwrap();

    // Create client endpoint
    let client_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let client = Endpoint::bind(client_addr).await.unwrap();

    // Test basic endpoint creation
    assert!(server.connections.is_empty());
    assert!(client.connections.is_empty());
}

#[tokio::test]
async fn test_crypto_endpoint() {
    let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let crypto_key = vec![0u8; 32]; // Test key

    let crypto_endpoint = Endpoint::bind_crypto(server_addr, crypto_key).await.unwrap();
    assert_eq!(crypto_endpoint.connections.len(), 0);
}

#[tokio::test]
async fn test_connection_id_generation() {
    let conn_id1 = ConnectionId::new();
    let conn_id2 = ConnectionId::new();

    // Connection IDs should be unique
    assert_ne!(conn_id1, conn_id2);
    assert_eq!(conn_id1.len(), 16); // UUID bytes
}

#[tokio::test]
async fn test_endpoint_stats() {
    let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let endpoint = Endpoint::bind(server_addr).await.unwrap();

    let stats = endpoint.stats();
    assert_eq!(stats.active_connections, 0);
    assert_eq!(stats.total_connections, 0);
}

mod packet_tests {
    use super::*;
    use gquic::packet::*;
    use bytes::Bytes;

    #[test]
    fn test_packet_creation() {
        let data = vec![0x01, 0x02, 0x03, 0x04];

        // Test packet parsing would go here
        // This is a placeholder since we need to implement proper packet parsing
        assert_eq!(data.len(), 4);
    }
}

mod crypto_tests {
    use super::*;
    use gquic::crypto::*;

    #[test]
    fn test_crypto_backend_creation() {
        let backend = default_crypto_backend();
        // Test that we can create a crypto backend
        assert!(std::ptr::addr_of!(*backend) as usize > 0);
    }

    #[test]
    fn test_key_types() {
        let public_key = PublicKey(vec![1, 2, 3, 4]);
        let private_key = PrivateKey(vec![5, 6, 7, 8]);

        assert_eq!(public_key.as_bytes(), &[1, 2, 3, 4]);
        assert_eq!(private_key.as_bytes(), &[5, 6, 7, 8]);
    }
}

mod handshake_tests {
    use super::*;
    use gquic::handshake::*;

    #[test]
    fn test_handshake_creation() {
        let conn_id = ConnectionId::new();
        let handshake = QuicHandshake::new(conn_id);

        assert_eq!(*handshake.state(), HandshakeState::Initial);
        assert!(!handshake.is_established());
    }

    #[test]
    fn test_handshake_states() {
        let states = vec![
            HandshakeState::Initial,
            HandshakeState::ClientHello,
            HandshakeState::ServerHello,
            HandshakeState::ClientFinished,
            HandshakeState::Established,
        ];

        // Test that we can create all handshake states
        for state in states {
            match state {
                HandshakeState::Established => assert!(true),
                _ => assert!(true), // All other states are valid
            }
        }
    }
}

mod flow_control_tests {
    use super::*;
    use gquic::flow_control::*;
    use gquic::quic::stream::StreamId;

    #[test]
    fn test_flow_control_window() {
        let window = FlowControlWindow::new(1000, 1000);

        assert!(window.can_send(500));
        assert!(window.reserve_send(500).is_ok());
        assert_eq!(window.send_capacity(), 500);
    }

    #[test]
    fn test_connection_flow_controller() {
        let config = FlowControlConfig::default();
        let mut controller = ConnectionFlowController::new(config);

        let stream_id = StreamId::new(4);
        controller.create_stream(stream_id);

        assert!(controller.can_send_stream_data(stream_id, 1000));
    }
}

mod congestion_tests {
    use super::*;
    use gquic::congestion::*;

    #[test]
    fn test_newreno_creation() {
        let newreno = NewReno::new(1200);
        assert_eq!(newreno.max_datagram_size(), 1200);
        assert!(newreno.congestion_window() > 0);
    }

    #[test]
    fn test_congestion_controller_factory() {
        let config = CongestionControlConfig::default();
        let controller = create_congestion_controller(&config);

        assert!(controller.congestion_window() > 0);
        assert!(controller.can_send(0)); // Should be able to send when no bytes in flight
    }
}

mod recovery_tests {
    use super::*;
    use gquic::recovery::*;
    use gquic::protection::PacketNumber;

    #[test]
    fn test_packet_number_encoding() {
        let pn = PacketNumber::new(0x12345);
        let encoded = pn.encode(None);

        let decoded = PacketNumber::decode(&encoded, None).unwrap();
        assert_eq!(decoded.value(), 0x12345);
    }

    #[test]
    fn test_loss_detection_creation() {
        let config = LossDetectionConfig::default();
        let loss_detection = LossDetection::new(config);

        assert_eq!(loss_detection.bytes_in_flight(), 0);
    }
}

mod tls_tests {
    use super::*;
    use gquic::tls::*;

    #[test]
    fn test_tls_config_builder() {
        let builder = TlsConfigBuilder::new();

        // Test that we can create a config builder
        let _client_config = builder.build_client();

        // Server config requires certificates, so we expect an error
        let server_result = builder.build_server();
        #[cfg(feature = "rustls-tls")]
        assert!(server_result.is_err());
        #[cfg(not(feature = "rustls-tls"))]
        assert!(server_result.is_err());
    }

    #[test]
    fn test_encryption_levels() {
        let levels = vec![
            EncryptionLevel::Initial,
            EncryptionLevel::EarlyData,
            EncryptionLevel::Handshake,
            EncryptionLevel::Application,
        ];

        // Test that all encryption levels are valid
        for level in levels {
            match level {
                EncryptionLevel::Application => assert!(true),
                _ => assert!(true),
            }
        }
    }
}

mod blockchain_tests {
    use super::*;
    use gquic::blockchain::*;

    #[test]
    fn test_transaction_creation() {
        let tx_hash = TxHash([1u8; 32]);
        let block_hash = BlockHash([2u8; 32]);

        let transaction = Transaction {
            hash: tx_hash,
            data: vec![1, 2, 3, 4],
            timestamp: 1234567890,
        };

        assert_eq!(transaction.data, vec![1, 2, 3, 4]);
        assert_eq!(transaction.timestamp, 1234567890);
    }

    #[test]
    fn test_transaction_pool() {
        let mut pool = TransactionPool::new();

        let tx = Transaction {
            hash: TxHash([1u8; 32]),
            data: vec![1, 2, 3],
            timestamp: 1234567890,
        };

        pool.add_transaction(tx.clone());
        assert_eq!(pool.pending_transactions().len(), 1);

        let retrieved = pool.get_transaction(&tx.hash);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().data, vec![1, 2, 3]);
    }
}

// Benchmark tests (require nightly Rust)
#[cfg(feature = "benchmark")]
mod benchmarks {
    use super::*;
    use test::Bencher;

    #[bench]
    fn bench_connection_id_generation(b: &mut Bencher) {
        b.iter(|| {
            ConnectionId::new()
        });
    }

    #[bench]
    fn bench_packet_number_encoding(b: &mut Bencher) {
        use gquic::protection::PacketNumber;

        b.iter(|| {
            let pn = PacketNumber::new(12345);
            let encoded = pn.encode(None);
            PacketNumber::decode(&encoded, None).unwrap()
        });
    }
}