# 👻 ghostquic – The GhostChain QUIC Transport Layer (`gquic`)

**ghostquic** (internal crate: `gquic`) is a custom QUIC transport layer optimized for the GhostChain ecosystem. Built in Rust and tightly integrated with our `gcrypt` library, it provides secure, low-latency, multiplexed communication over UDP with first-class support for WalletD, GhostD, and other GhostBridge services.

---

## ✨ Features

* 🚀 **High-performance QUIC Core**

  * Built from scratch in Rust using `tokio` and zero-copy packet processing
  * Optimized for WalletD and GhostD workloads

* 🔐 **Cryptographic Integration**

  * Fully integrated with [`gcrypt`](https://github.com/ghostkellz/gcrypt)
  * Native TLS 1.3, AEAD, and key exchange handling

* 📦 **Service Multiplexing**

  * Supports HTTP/3, gRPC, and custom protocols over QUIC
  * Bidirectional + unidirectional stream support
  * Connection migration, session resumption (0-RTT)

* 🌐 **IPv6-Ready Edge Transport**

  * QUIC endpoint abstraction for port 443 multiplexing
  * ALPN, SNI, and custom routing via `GhostBridge`

* 📊 **Observability**

  * Built-in telemetry, connection health, and performance metrics
  * Optional Prometheus endpoint or JSON logging

---

## 🧱 Architecture

```
               ┌──────────────────┐
               │  walletd   │
               └──────────────────┘
                     │ FFI/gRPC
               ┌──────────────────┐
               │   gquic    │ ← crate
               └──────────────────┘
          Rust QUIC core + gcrypt integration
                     │
             UDP socket (tokio)
                     │
              ╭─────────────────────╮
              │ ghostquicd │ ← CLI or daemon mode
              ╰─────────────────────╯
```

---

## ⚙️ Getting Started

### 1. 📦 Install

```bash
git clone https://github.com/ghostkellz/gquic
cd gquic
cargo build --release
```

### 2. 🛠️ Example: Start a QUIC Server

```rust
use gquic::server::QuicServerConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = QuicServerConfig::builder()
        .bind("0.0.0.0:443")
        .with_tls("certs/fullchain.pem", "certs/privkey.pem")
        .enable_ipv6()
        .with_multiplexing()
        .build();

    gquic::server::run(config).await?;
    Ok(())
}
```

### 3. 🦪 Example: QUIC Client

```rust
use gquic::client::QuicClient;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = QuicClient::builder()
        .endpoint("https://ghostbridge.local:443")
        .with_alpn("h3")
        .with_tls()
        .build();

    let stream = client.open_bi_stream("walletd").await?;
    stream.write_all(b"ping").await?;
    Ok(())
}
```

---

## 🧼 Integration Targets

| Project       | Integration  | Role                            |
| ------------- | ------------ | ------------------------------- |
| `walletd`     | FFI/gRPC     | Transport layer for signing ops |
| `ghostd`      | FFI/gRPC     | Chain gossip, consensus, state  |
| `ghostbridge` | Routed Proxy | SNI, gRPC-web, QUIC <-> HTTP/3  |
| `wraith`      | Edge Router  | QUIC relay with DNS/ZNS logic   |

---

## 🔐 Security Model

* TLS 1.3 handshake via `gcrypt`
* Optional key pinning and identity handshake
* QUIC-level stream isolation
* Stateless retry and DoS prevention built-in

---

## 🧠 Design Goals

| Goal                              | Status |
| --------------------------------- | ------ |
| 🔐 Consistent crypto via `gcrypt` | ✅      |
| ⚡ Minimal latency QUIC core       | ✅      |
| 🌍 IPv6 + edge support            | ✅      |
| ⚙️ WalletD/Identity-ready         | ✅      |
| 🧪 Unit + integration tested      | ✅      |
| 🌐 QUIC ↔ HTTP/3 fallback         | ✅      |

---

## 📜 License

MIT © 2025 [GhostKellz](https://github.com/ghostkellz)

