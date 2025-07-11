//! Blockchain integration for GQUIC

use crate::{QuicResult, QuicError, Frame, Connection};
use crate::crypto::{CryptoBackend, PublicKey, Signature, default_crypto_backend};
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;

/// Transaction hash type
pub type TxHash = [u8; 32];

/// Block hash type  
pub type BlockHash = [u8; 32];

/// Blockchain transaction
#[derive(Debug, Clone)]
pub struct Transaction {
    pub id: TxHash,
    pub from: PublicKey,
    pub to: PublicKey,
    pub amount: u64,
    pub data: Vec<u8>,
    pub signature: Signature,
    pub timestamp: u64,
}

impl Transaction {
    pub fn new(
        from: PublicKey,
        to: PublicKey,
        amount: u64,
        data: Vec<u8>,
        timestamp: u64,
    ) -> Self {
        let mut tx = Self {
            id: [0u8; 32],
            from,
            to,
            amount,
            data,
            signature: Signature(vec![]),
            timestamp,
        };
        tx.id = tx.compute_hash();
        tx
    }
    
    pub fn compute_hash(&self) -> TxHash {
        // Simple hash computation (in production use a proper hash function)
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        use std::hash::{Hash, Hasher};
        
        self.from.as_bytes().hash(&mut hasher);
        self.to.as_bytes().hash(&mut hasher);
        self.amount.hash(&mut hasher);
        self.data.hash(&mut hasher);
        self.timestamp.hash(&mut hasher);
        
        let hash = hasher.finish();
        let mut result = [0u8; 32];
        result[..8].copy_from_slice(&hash.to_be_bytes());
        result
    }
    
    pub fn serialize(&self) -> Vec<u8> {
        let mut serialized = Vec::new();
        serialized.extend_from_slice(&self.id);
        serialized.extend_from_slice(self.from.as_bytes());
        serialized.extend_from_slice(self.to.as_bytes());
        serialized.extend_from_slice(&self.amount.to_be_bytes());
        serialized.extend_from_slice(&(self.data.len() as u32).to_be_bytes());
        serialized.extend_from_slice(&self.data);
        serialized.extend_from_slice(&self.timestamp.to_be_bytes());
        serialized
    }
    
    pub fn sign(&mut self, crypto_backend: &dyn CryptoBackend, private_key: &crate::crypto::PrivateKey) -> QuicResult<()> {
        let data = self.serialize();
        self.signature = crypto_backend.sign(&data, private_key)?;
        Ok(())
    }
    
    pub fn verify(&self, crypto_backend: &dyn CryptoBackend) -> QuicResult<bool> {
        let data = self.serialize();
        crypto_backend.verify(&data, &self.signature, &self.from)
    }
}

/// Blockchain block
#[derive(Debug, Clone)]
pub struct Block {
    pub hash: BlockHash,
    pub previous_hash: BlockHash,
    pub transactions: Vec<Transaction>,
    pub timestamp: u64,
    pub nonce: u64,
}

impl Block {
    pub fn new(previous_hash: BlockHash, transactions: Vec<Transaction>, timestamp: u64) -> Self {
        let mut block = Self {
            hash: [0u8; 32],
            previous_hash,
            transactions,
            timestamp,
            nonce: 0,
        };
        block.hash = block.compute_hash();
        block
    }
    
    pub fn compute_hash(&self) -> BlockHash {
        // Simple hash computation
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        use std::hash::{Hash, Hasher};
        
        self.previous_hash.hash(&mut hasher);
        for tx in &self.transactions {
            tx.id.hash(&mut hasher);
        }
        self.timestamp.hash(&mut hasher);
        self.nonce.hash(&mut hasher);
        
        let hash = hasher.finish();
        let mut result = [0u8; 32];
        result[..8].copy_from_slice(&hash.to_be_bytes());
        result
    }
    
    pub fn serialize(&self) -> Vec<u8> {
        let mut serialized = Vec::new();
        serialized.extend_from_slice(&self.hash);
        serialized.extend_from_slice(&self.previous_hash);
        serialized.extend_from_slice(&(self.transactions.len() as u32).to_be_bytes());
        for tx in &self.transactions {
            let tx_data = tx.serialize();
            serialized.extend_from_slice(&(tx_data.len() as u32).to_be_bytes());
            serialized.extend_from_slice(&tx_data);
        }
        serialized.extend_from_slice(&self.timestamp.to_be_bytes());
        serialized.extend_from_slice(&self.nonce.to_be_bytes());
        serialized
    }
}

/// Transaction pool for managing pending transactions
pub struct TransactionPool {
    pending: Arc<RwLock<HashMap<TxHash, Transaction>>>,
    confirmed: Arc<RwLock<HashMap<TxHash, Transaction>>>,
    crypto_backend: Arc<dyn CryptoBackend>,
}

impl TransactionPool {
    pub fn new() -> Self {
        Self {
            pending: Arc::new(RwLock::new(HashMap::new())),
            confirmed: Arc::new(RwLock::new(HashMap::new())),
            crypto_backend: default_crypto_backend(),
        }
    }
    
    pub fn with_crypto_backend(backend: Arc<dyn CryptoBackend>) -> Self {
        Self {
            pending: Arc::new(RwLock::new(HashMap::new())),
            confirmed: Arc::new(RwLock::new(HashMap::new())),
            crypto_backend: backend,
        }
    }
    
    /// Add transaction to pending pool
    pub async fn add_transaction(&self, tx: Transaction) -> QuicResult<()> {
        // Verify transaction signature
        if !tx.verify(self.crypto_backend.as_ref())? {
            return Err(QuicError::AuthenticationFailed("Invalid transaction signature".to_string()));
        }
        
        let mut pending = self.pending.write().unwrap();
        pending.insert(tx.id, tx);
        Ok(())
    }
    
    /// Get pending transactions
    pub async fn get_pending_transactions(&self) -> Vec<Transaction> {
        let pending = self.pending.read().unwrap();
        pending.values().cloned().collect()
    }
    
    /// Move transaction from pending to confirmed
    pub async fn confirm_transaction(&self, tx_hash: &TxHash) -> QuicResult<()> {
        let mut pending = self.pending.write().unwrap();
        let mut confirmed = self.confirmed.write().unwrap();
        
        if let Some(tx) = pending.remove(tx_hash) {
            confirmed.insert(*tx_hash, tx);
            Ok(())
        } else {
            Err(QuicError::BlockchainError("Transaction not found in pending pool".to_string()))
        }
    }
    
    /// Broadcast transaction to network via QUIC
    pub async fn broadcast_transaction(&self, tx: Transaction, connections: &[Connection]) -> QuicResult<()> {
        let frame = Frame::BlockchainData {
            chain_id: 1, // Placeholder chain ID
            block_hash: Bytes::from(tx.id.to_vec()),
            data: Bytes::from(tx.serialize()),
        };
        
        let encoded_frame = frame.encode_crypto();
        
        for connection in connections {
            if let Err(e) = connection.send(&encoded_frame).await {
                eprintln!("Failed to broadcast transaction to connection {:?}: {}", connection.id(), e);
            }
        }
        
        Ok(())
    }
    
    /// Handle incoming blockchain frame
    pub async fn handle_blockchain_frame(&self, frame: Frame) -> QuicResult<()> {
        match frame {
            Frame::BlockchainData { chain_id: _, block_hash: _, data } => {
                // Try to deserialize as transaction
                if let Ok(tx) = self.deserialize_transaction(&data) {
                    self.add_transaction(tx).await?;
                }
                Ok(())
            }
            _ => Err(QuicError::Protocol("Not a blockchain frame".to_string()))
        }
    }
    
    fn deserialize_transaction(&self, data: &[u8]) -> QuicResult<Transaction> {
        // Simple deserialization (in production use a proper serialization format)
        if data.len() < 32 + 64 + 8 + 4 + 8 { // id + keys + amount + data_len + timestamp
            return Err(QuicError::BlockchainError("Invalid transaction data".to_string()));
        }
        
        let mut offset = 0;
        
        let mut id = [0u8; 32];
        id.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;
        
        let from = PublicKey(data[offset..offset + 32].to_vec());
        offset += 32;
        
        let to = PublicKey(data[offset..offset + 32].to_vec());
        offset += 32;
        
        let amount = u64::from_be_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
            data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
        ]);
        offset += 8;
        
        let data_len = u32::from_be_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        ]) as usize;
        offset += 4;
        
        if data.len() < offset + data_len + 8 {
            return Err(QuicError::BlockchainError("Invalid transaction data length".to_string()));
        }
        
        let tx_data = data[offset..offset + data_len].to_vec();
        offset += data_len;
        
        let timestamp = u64::from_be_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
            data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
        ]);
        
        Ok(Transaction {
            id,
            from,
            to,
            amount,
            data: tx_data,
            signature: Signature(vec![]), // Signature would be included in full implementation
            timestamp,
        })
    }
    
    /// Get pool statistics
    pub async fn stats(&self) -> TransactionPoolStats {
        let pending = self.pending.read().unwrap();
        let confirmed = self.confirmed.read().unwrap();
        
        TransactionPoolStats {
            pending_count: pending.len(),
            confirmed_count: confirmed.len(),
        }
    }
}

#[derive(Debug)]
pub struct TransactionPoolStats {
    pub pending_count: usize,
    pub confirmed_count: usize,
}

impl Default for TransactionPool {
    fn default() -> Self {
        Self::new()
    }
}
