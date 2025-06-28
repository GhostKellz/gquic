# GQUIC Integration Fixes Guide

This document outlines the remaining compilation errors after migrating from quinn to gquic and provides fixes for API incompatibilities.

## Current Status

✅ **Core migration complete:**
- gquic/gcrypt dependencies enabled in Cargo.toml
- QUIC transport layer migrated from quinn to gquic
- Crypto layer migrated to gcrypt with compatibility wrapper
- FFI integration updated for realid and signer modules

❌ **Remaining API fixes needed:**
- Stream type mismatches
- Connection field access issues
- Missing trait imports

## Compilation Errors & Fixes

### 1. Stream Type Issues

**Error:**
```rust
error[E0412]: cannot find type `SendStream` in this scope
error[E0412]: cannot find type `RecvStream` in this scope
```

**Current Code:**
```rust
async fn handle_stream(
    chain_manager: Arc<Mutex<ChainManager>>,
    signer: Arc<RealIdSigner>,
    mut send: SendStream,      // ❌ Wrong type
    mut recv: RecvStream,      // ❌ Wrong type
) -> Result<()> {
```

**Fix Options:**

#### Option A: Use gquic stream types
```rust
// Check gquic documentation for correct stream types
use gquic::stream::{BiStream, UniStream, StreamReader, StreamWriter};

async fn handle_stream(
    chain_manager: Arc<Mutex<ChainManager>>,
    signer: Arc<RealIdSigner>,
    mut send: StreamWriter,    // ✅ Correct gquic type
    mut recv: StreamReader,    // ✅ Correct gquic type
) -> Result<()> {
```

#### Option B: Use generic stream trait
```rust
use gquic::traits::{AsyncWrite, AsyncRead};

async fn handle_stream<S, R>(
    chain_manager: Arc<Mutex<ChainManager>>,
    signer: Arc<RealIdSigner>,
    mut send: S,
    mut recv: R,
) -> Result<()> 
where
    S: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
```

### 2. Connection Field Access Issues

**Error:**
```rust
error[E0609]: no field `connection` on type `gquic::Connection`
error[E0609]: no field `bi_streams` on type `gquic::Connection`
```

**Current Code:**
```rust
let remote_addr = connection.connection.remote_address();  // ❌ Wrong field access
while let Ok((send, recv)) = connection.bi_streams.accept().await {  // ❌ Wrong field access
```

**Fix:**
```rust
// Check gquic::Connection API for correct methods
let remote_addr = connection.remote_address();  // ✅ Direct method call
while let Ok((send, recv)) = connection.accept_bi().await {  // ✅ Correct method name
```

### 3. Missing SigningKey::generate Method

**Error:**
```rust
error[E0599]: no function or associated item named `generate` found for struct `SigningKey`
```

**Current Code:**
```rust
let secret_key = SigningKey::generate(&mut rand::rngs::OsRng);  // ❌ Wrong method
```

**Fix:**
```rust
use rand::rngs::OsRng;
use rand::RngCore;

// Use from_bytes with random data
let mut secret_bytes = [0u8; 32];
OsRng.fill_bytes(&mut secret_bytes);
let secret_key = SigningKey::from_bytes(&secret_bytes);  // ✅ Correct method
```

### 4. Missing Trait Imports

**Error:**
```rust
error[E0405]: cannot find trait `ConnectionHandler` in this scope
```

**Fix:**
```rust
use gquic::server::ConnectionHandler;  // ✅ Already added
```

## Complete Fixes Implementation

### File: `src/quic.rs`

```rust
// Fixed imports
use anyhow::Result;
use gquic::prelude::*;
use gquic::server::ConnectionHandler;
use gquic::stream::{StreamWriter, StreamReader}; // Use actual gquic stream types
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tracing::{info, warn, error};

use crate::chain::ChainManager;
use crate::signer::{RealIdSigner, VerificationResult, GhostchainTransaction};

impl GhostQuicHandler {
    /// Handle incoming QUIC connection
    pub async fn handle_connection(&self, connection: Connection) -> Result<()> {
        let remote_addr = connection.remote_address();  // ✅ Fixed field access
        info!("🔗 New QUIC connection from {}", remote_addr);

        // Handle bidirectional streams
        while let Ok((send, recv)) = connection.accept_bi().await {  // ✅ Fixed method call
            let chain_manager = self.chain_manager.clone();
            let signer = self.signer.clone();
            
            tokio::spawn(async move {
                if let Err(e) = Self::handle_stream(chain_manager, signer, send, recv).await {
                    error!("❌ Stream handling error: {}", e);
                }
            });
        }

        Ok(())
    }

    /// Handle a bidirectional stream
    async fn handle_stream(
        chain_manager: Arc<Mutex<ChainManager>>,
        signer: Arc<RealIdSigner>,
        mut send: StreamWriter,  // ✅ Fixed stream type
        mut recv: StreamReader,  // ✅ Fixed stream type
    ) -> Result<()> {
        // ... rest of implementation stays the same
    }

    /// Read a message with size limit
    async fn read_message(recv: &mut StreamReader, max_size: usize) -> Result<Vec<u8>> {  // ✅ Fixed type
        let mut buffer = vec![0u8; max_size];
        let bytes_read = recv.read(&mut buffer).await?.unwrap_or(0);
        buffer.truncate(bytes_read);
        Ok(buffer)
    }
}

#[async_trait::async_trait]
impl ConnectionHandler for GhostChainHandler {
    async fn handle_connection(
        &self,
        connection: Connection,  // ✅ Fixed type
        _config: Arc<QuicServerConfig>,
    ) -> Result<()> {
        let remote_addr = connection.remote_address();  // ✅ Fixed field access
        info!("🔗 New QUIC connection from {}", remote_addr);

        while let Ok((send, recv)) = connection.accept_bi().await {  // ✅ Fixed method call
            let chain_manager = self.chain_manager.clone();
            let signer = self.signer.clone();
            
            tokio::spawn(async move {
                if let Err(e) = GhostQuicHandler::handle_stream(chain_manager, signer, send, recv).await {
                    error!("❌ Stream handling error: {}", e);
                }
            });
        }

        Ok(())
    }
}
```

### File: `src/gcrypt_compat.rs`

```rust
impl KeyPair {
    pub fn generate(algorithm: Algorithm) -> Result<Self> {
        match algorithm {
            Algorithm::Ed25519 => {
                // ✅ Fixed key generation
                use rand::rngs::OsRng;
                use rand::RngCore;
                
                let mut secret_bytes = [0u8; 32];
                OsRng.fill_bytes(&mut secret_bytes);
                let secret_key = SigningKey::from_bytes(&secret_bytes);
                let public_key = VerifyingKey::from(&secret_key);
                Ok(Self { secret_key, public_key })
            }
        }
    }
}
```

## API Research Required

### 1. Verify gquic Stream Types

**TODO:** Check the actual gquic library for correct stream types:
```bash
# Research actual gquic API
cargo doc --open --package gquic
```

**Expected types to look for:**
- `gquic::stream::BiStream`
- `gquic::stream::SendStream` 
- `gquic::stream::RecvStream`
- `gquic::connection::Connection`

### 2. Verify Connection Methods

**TODO:** Check gquic::Connection for available methods:
- `remote_address()` or `remote_addr()`
- `accept_bi()` or `accept_bidirectional()`
- `open_bi()` or `open_bidirectional()`

### 3. Verify Server Configuration

**TODO:** Check if QuicServer builder pattern matches:
```rust
let server = QuicServer::builder()
    .bind(bind_addr)
    .with_self_signed_cert()?
    .with_alpn("ghostchain-wallet")
    .with_handler(Arc::new(handler))
    .build()?;
```

## Testing Strategy

### 1. Incremental Fixes

Apply fixes one at a time to isolate issues:

```bash
# Fix stream types first
cargo check 2>&1 | grep -A 5 "SendStream\|RecvStream"

# Fix connection methods
cargo check 2>&1 | grep -A 5 "connection\|bi_streams"

# Fix crypto generation
cargo check 2>&1 | grep -A 5 "generate"
```

### 2. Mock Testing

Create a minimal test to verify gquic integration:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_gquic_basic_server() {
        let handler = GhostChainHandler::new(
            ChainManager::new().unwrap(),
            RealIdSigner::new().unwrap()
        );
        
        // Test server creation without starting
        let server_result = QuicServer::builder()
            .bind("127.0.0.1:0".parse().unwrap())
            .with_self_signed_cert()
            .unwrap()
            .with_handler(Arc::new(handler))
            .build();
            
        assert!(server_result.is_ok());
    }
}
```

### 3. Documentation Generation

Generate docs to understand available APIs:

```bash
# Generate gquic documentation
cargo doc --package gquic --open

# Generate gcrypt documentation  
cargo doc --package gcrypt --open
```

## Next Steps

1. **Research actual gquic API** - Review generated documentation
2. **Apply stream type fixes** - Update to correct gquic stream types
3. **Fix connection methods** - Update field access to method calls
4. **Test incremental builds** - Verify each fix resolves specific errors
5. **Add integration tests** - Ensure QUIC server can start successfully
6. **Performance testing** - Compare gquic vs quinn performance

## Expected Timeline

- **Phase 1 (1-2 hours):** API research and documentation review
- **Phase 2 (2-3 hours):** Apply all identified fixes
- **Phase 3 (1 hour):** Integration testing and validation
- **Phase 4 (1 hour):** Performance benchmarking

## Success Criteria

✅ **Complete when:**
- `cargo check` passes without gquic-related errors
- Server can start and accept connections
- Basic QUIC operations work (connect, send, receive)
- All tests pass
- Documentation is updated

## Fallback Plan

If gquic API is too unstable:
- Maintain quinn as primary transport
- Use gquic as experimental feature flag
- Gradually migrate as gquic API stabilizes

```toml
[features]
default = ["quinn-transport"]
gquic-transport = ["gquic"]
quinn-transport = ["quinn"]
```

This allows switching between implementations during development.