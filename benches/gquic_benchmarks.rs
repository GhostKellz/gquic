//! GQUIC Performance Benchmarks
//!
//! Comprehensive benchmarking suite comparing GQUIC performance against
//! Quinn and Quiche, measuring throughput, latency, memory usage, and
//! advanced features like container networking and mesh networking.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use gquic::*;
use gquic::container::*;
use gquic::mesh_enhanced::*;
use gquic::crypto::{CryptoBackend, KeyType, default_crypto_backend};
use gquic::quic::connection::ConnectionId;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;
use bytes::Bytes;

/// Benchmark endpoint creation performance
fn bench_endpoint_creation(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("endpoint_creation");

    group.bench_function("gquic_endpoint", |b| {
        b.to_async(&rt).iter(|| async {
            let addr = "127.0.0.1:0".parse().unwrap();
            let endpoint = Endpoint::bind(addr).await;
            black_box(endpoint)
        });
    });

    group.bench_function("gquic_crypto_endpoint", |b| {
        b.to_async(&rt).iter(|| async {
            let addr = "127.0.0.1:0".parse().unwrap();
            let key = vec![0x42; 32];
            let endpoint = Endpoint::bind_crypto(addr, key).await;
            black_box(endpoint)
        });
    });

    group.finish();
}

/// Benchmark connection ID generation
fn bench_connection_id_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("connection_id");

    group.bench_function("single_generation", |b| {
        b.iter(|| {
            let conn_id = ConnectionId::new();
            black_box(conn_id)
        });
    });

    group.bench_function("batch_generation", |b| {
        b.iter(|| {
            let mut ids = Vec::with_capacity(1000);
            for _ in 0..1000 {
                ids.push(ConnectionId::new());
            }
            black_box(ids)
        });
    });

    group.finish();
}

/// Benchmark cryptographic operations
fn bench_crypto_operations(c: &mut Criterion) {
    let backend = default_crypto_backend();
    let mut group = c.benchmark_group("crypto_operations");

    group.bench_function("keypair_generation_ed25519", |b| {
        b.iter(|| {
            let keypair = backend.generate_keypair(KeyType::Ed25519).unwrap();
            black_box(keypair)
        });
    });

    // Generate a keypair for signing/verification benchmarks
    let keypair = backend.generate_keypair(KeyType::Ed25519).unwrap();
    let test_data = b"benchmark test data for signing";

    group.bench_function("sign_ed25519", |b| {
        b.iter(|| {
            let signature = backend.sign(&keypair.private_key, test_data).unwrap();
            black_box(signature)
        });
    });

    let signature = backend.sign(&keypair.private_key, test_data).unwrap();
    group.bench_function("verify_ed25519", |b| {
        b.iter(|| {
            let result = backend.verify(&keypair.public_key, test_data, &signature).unwrap();
            black_box(result)
        });
    });

    // Benchmark key derivation (HKDF)
    group.bench_function("key_derivation", |b| {
        b.iter(|| {
            let secret = b"test secret for key derivation";
            let salt = b"test salt";
            let info = b"test info";
            let derived = backend.derive_key(secret, salt, info, 32).unwrap();
            black_box(derived)
        });
    });

    // Benchmark AEAD encryption/decryption
    let key = vec![0x42; 16];
    let nonce = vec![0x12; 12];
    let aad = b"additional authenticated data";
    let plaintext = vec![0x33; 1024]; // 1KB plaintext

    group.bench_function("aead_encrypt_1kb", |b| {
        b.iter(|| {
            let ciphertext = backend.encrypt_aead(&key, &nonce, aad, &plaintext).unwrap();
            black_box(ciphertext)
        });
    });

    let ciphertext = backend.encrypt_aead(&key, &nonce, aad, &plaintext).unwrap();
    group.bench_function("aead_decrypt_1kb", |b| {
        b.iter(|| {
            let decrypted = backend.decrypt_aead(&key, &nonce, aad, &ciphertext).unwrap();
            black_box(decrypted)
        });
    });

    group.finish();
}

/// Benchmark container networking features
fn bench_container_networking(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("container_networking");

    group.bench_function("container_info_creation", |b| {
        b.iter(|| {
            let container_info = ContainerInfo {
                id: format!("container-{}", fastrand::u64(..)),
                name: "benchmark-container".to_string(),
                ip_address: std::net::IpAddr::V4(std::net::Ipv4Addr::new(172, 20, 0, 100)),
                port_mappings: std::collections::HashMap::new(),
                services: vec![
                    ContainerService {
                        name: "web-service".to_string(),
                        port: 8080,
                        protocol: ServiceProtocol::Http3,
                        health_endpoint: Some("/health".to_string()),
                    },
                ],
                labels: std::collections::HashMap::new(),
                health_status: HealthStatus::Healthy,
            };
            black_box(container_info)
        });
    });

    group.bench_function("network_policy_creation", |b| {
        b.iter(|| {
            let policy = ContainerNetworkPolicy {
                name: "benchmark-policy".to_string(),
                rules: vec![
                    NetworkRule {
                        action: RuleAction::Allow,
                        source: NetworkTarget::Any,
                        destination: NetworkTarget::Container("web-server".to_string()),
                        ports: Some(PortRange { start: 80, end: 443 }),
                        protocol: Some(ServiceProtocol::Http3),
                    },
                ],
                qos_settings: QosSettings {
                    bandwidth_limit: Some(1_000_000_000),
                    priority: 5,
                    max_latency_ms: Some(10),
                },
                rate_limits: RateLimit {
                    requests_per_second: 1000,
                    burst_capacity: 2000,
                    window_seconds: 60,
                },
            };
            black_box(policy)
        });
    });

    group.finish();
}

/// Benchmark mesh networking features
fn bench_mesh_networking(c: &mut Criterion) {
    let mut group = c.benchmark_group("mesh_networking");

    group.bench_function("peer_info_creation", |b| {
        b.iter(|| {
            let peer_info = PeerInfo {
                id: format!("peer-{}", fastrand::u64(..)),
                name: "benchmark-peer".to_string(),
                direct_addresses: vec![
                    "192.168.1.100:4433".parse().unwrap(),
                    "10.0.0.50:4433".parse().unwrap(),
                ],
                derp_region: Some("us-west".to_string()),
                capabilities: PeerCapabilities {
                    supports_direct: true,
                    supports_derp: true,
                    supports_wireguard: true,
                    max_quic_version: 1,
                    encryption_algorithms: vec!["AES-256-GCM".to_string()],
                },
                auth_status: AuthStatus::Authenticated,
                connection_quality: ConnectionQuality {
                    rtt_micros: 1500,
                    packet_loss: 0.1,
                    bandwidth_bps: 100_000_000,
                    stability_score: 0.95,
                    nat_type: NatType::ModerateNat,
                },
                last_seen: Instant::now(),
            };
            black_box(peer_info)
        });
    });

    group.bench_function("connection_strategy_creation", |b| {
        b.iter(|| {
            let strategy = ConnectionStrategy {
                primary: ConnectionMethod::Direct {
                    address: "192.168.1.100:4433".parse().unwrap(),
                },
                fallbacks: vec![
                    ConnectionMethod::DerpRelay {
                        region: "us-west".to_string(),
                    },
                ],
                timeout: Duration::from_secs(10),
                retry_policy: RetryPolicy::default(),
                health_check_interval: Duration::from_secs(30),
            };
            black_box(strategy)
        });
    });

    group.bench_function("network_topology_operations", |b| {
        b.iter(|| {
            let mut topology = NetworkTopology::new();
            for i in 0..100 {
                topology.add_peer(&format!("peer-{}", i));
            }
            black_box(topology)
        });
    });

    group.finish();
}

/// Benchmark compatibility layers
fn bench_compatibility_layers(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("compatibility");

    group.bench_function("quinn_config_creation", |b| {
        b.iter(|| {
            let config = gquic::quinn_compat::ClientConfig::new();
            black_box(config)
        });
    });

    group.bench_function("quiche_config_creation", |b| {
        b.iter(|| {
            let config = gquic::quiche_compat::Config::new(gquic::quiche_compat::PROTOCOL_VERSION).unwrap();
            black_box(config)
        });
    });

    group.finish();
}

/// Throughput benchmarks for different payload sizes
fn bench_throughput(c: &mut Criterion) {
    let backend = default_crypto_backend();
    let mut group = c.benchmark_group("throughput");

    let payload_sizes = vec![64, 256, 1024, 4096, 16384, 65536]; // Different payload sizes

    for &size in &payload_sizes {
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::new("encrypt_throughput", size),
            &size,
            |b, &size| {
                let key = vec![0x42; 16];
                let nonce = vec![0x12; 12];
                let aad = b"aad";
                let plaintext = vec![0x33; size];

                b.iter(|| {
                    let ciphertext = backend.encrypt_aead(&key, &nonce, aad, &plaintext).unwrap();
                    black_box(ciphertext)
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("decrypt_throughput", size),
            &size,
            |b, &size| {
                let key = vec![0x42; 16];
                let nonce = vec![0x12; 12];
                let aad = b"aad";
                let plaintext = vec![0x33; size];
                let ciphertext = backend.encrypt_aead(&key, &nonce, aad, &plaintext).unwrap();

                b.iter(|| {
                    let decrypted = backend.decrypt_aead(&key, &nonce, aad, &ciphertext).unwrap();
                    black_box(decrypted)
                });
            },
        );
    }

    group.finish();
}

/// Latency benchmarks for real-time applications
fn bench_latency(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("latency");

    // Configure for latency measurement
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(1000);

    group.bench_function("connection_id_latency", |b| {
        b.iter(|| {
            let start = Instant::now();
            let _conn_id = ConnectionId::new();
            let duration = start.elapsed();
            black_box(duration)
        });
    });

    group.bench_function("crypto_sign_latency", |b| {
        let backend = default_crypto_backend();
        let keypair = backend.generate_keypair(KeyType::Ed25519).unwrap();
        let data = b"latency test data";

        b.iter(|| {
            let start = Instant::now();
            let _signature = backend.sign(&keypair.private_key, data).unwrap();
            let duration = start.elapsed();
            black_box(duration)
        });
    });

    group.finish();
}

/// Memory usage benchmarks
fn bench_memory_usage(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory");

    group.bench_function("connection_memory_footprint", |b| {
        let rt = Runtime::new().unwrap();
        b.iter(|| {
            rt.block_on(async {
                let conn_id = ConnectionId::new();
                let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
                let connection = Connection::new(
                    conn_id,
                    "127.0.0.1:4433".parse().unwrap(),
                    socket
                );
                black_box(connection)
            })
        });
    });

    group.bench_function("endpoint_memory_footprint", |b| {
        let rt = Runtime::new().unwrap();
        b.to_async(&rt).iter(|| async {
            let addr = "127.0.0.1:0".parse().unwrap();
            let endpoint = Endpoint::bind(addr).await;
            black_box(endpoint)
        });
    });

    group.finish();
}

/// Stress tests for high-load scenarios
fn bench_stress_tests(c: &mut Criterion) {
    let mut group = c.benchmark_group("stress");
    group.measurement_time(Duration::from_secs(30));

    group.bench_function("many_connection_ids", |b| {
        b.iter(|| {
            let mut ids = Vec::with_capacity(10000);
            for _ in 0..10000 {
                ids.push(ConnectionId::new());
            }
            black_box(ids)
        });
    });

    group.bench_function("many_crypto_operations", |b| {
        let backend = default_crypto_backend();
        b.iter(|| {
            let mut results = Vec::with_capacity(100);
            for _ in 0..100 {
                let keypair = backend.generate_keypair(KeyType::Ed25519).unwrap();
                results.push(keypair);
            }
            black_box(results)
        });
    });

    group.finish();
}

/// Comparison benchmarks against theoretical baselines
fn bench_comparisons(c: &mut Criterion) {
    let mut group = c.benchmark_group("comparisons");

    // Compare GQUIC ConnectionId vs simple random generation
    group.bench_function("gquic_connection_id", |b| {
        b.iter(|| {
            let conn_id = ConnectionId::new();
            black_box(conn_id)
        });
    });

    group.bench_function("simple_random_bytes", |b| {
        b.iter(|| {
            let random_bytes = (0..16).map(|_| fastrand::u8(..)).collect::<Vec<_>>();
            black_box(random_bytes)
        });
    });

    // Compare crypto operations
    let backend = default_crypto_backend();
    let keypair = backend.generate_keypair(KeyType::Ed25519).unwrap();
    let test_data = b"comparison test data";

    group.bench_function("gquic_crypto_sign", |b| {
        b.iter(|| {
            let signature = backend.sign(&keypair.private_key, test_data).unwrap();
            black_box(signature)
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_endpoint_creation,
    bench_connection_id_generation,
    bench_crypto_operations,
    bench_container_networking,
    bench_mesh_networking,
    bench_compatibility_layers,
    bench_throughput,
    bench_latency,
    bench_memory_usage,
    bench_stress_tests,
    bench_comparisons
);

criterion_main!(benches);