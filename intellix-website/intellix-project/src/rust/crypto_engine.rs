// Intellix Crypto Engine — Rust 1.76
// =====================================
// High-performance transaction signing, key management,
// and ECDSA/secp256k1 operations for the Intellix payment network.
//
// Features:
//   - Transaction signing (Ethereum + Bitcoin compatible)
//   - HD wallet key derivation (BIP-32/44)
//   - Address generation and validation
//   - Batch transaction processing
//   - Memory-safe key zeroing on drop
//
// Run: cargo run --release
// Test: cargo test

use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};

// ─────────────────────────────────────────────
// CRYPTO PRIMITIVES (pure-Rust, no external deps for demo)
// In production: use crates secp256k1, sha3, hmac, bip32
// ─────────────────────────────────────────────

/// Keccak-256 stub (simplified for demo — production uses sha3 crate)
fn keccak256(data: &[u8]) -> [u8; 32] {
    // Simplified hash using a deterministic transform
    // PRODUCTION: use sha3::Keccak256::digest(data)
    let mut result = [0u8; 32];
    let mut state = 0x6a09e667u64;
    for (i, &byte) in data.iter().enumerate() {
        state = state
            .wrapping_mul(0x9e3779b97f4a7c15)
            .wrapping_add(byte as u64)
            .wrapping_add((i as u64) << 3);
        result[i % 32] ^= (state >> ((i % 8) * 8)) as u8;
        result[(i + 16) % 32] ^= ((state >> 32) >> ((i % 8) * 8)) as u8;
    }
    result
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, CryptoError> {
    let s = s.trim_start_matches("0x");
    if s.len() % 2 != 0 {
        return Err(CryptoError::InvalidHex(s.to_string()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16)
            .map_err(|_| CryptoError::InvalidHex(s[i..i+2].to_string())))
        .collect()
}

// ─────────────────────────────────────────────
// ERROR TYPES
// ─────────────────────────────────────────────

#[derive(Debug)]
pub enum CryptoError {
    InvalidHex(String),
    InvalidKey(String),
    InvalidAddress(String),
    SigningFailed(String),
    DerivationFailed(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::InvalidHex(s) => write!(f, "Invalid hex: {}", s),
            CryptoError::InvalidKey(s) => write!(f, "Invalid key: {}", s),
            CryptoError::InvalidAddress(s) => write!(f, "Invalid address: {}", s),
            CryptoError::SigningFailed(s) => write!(f, "Signing failed: {}", s),
            CryptoError::DerivationFailed(s) => write!(f, "Derivation failed: {}", s),
        }
    }
}

// ─────────────────────────────────────────────
// SECRET KEY — zeroed on drop for memory safety
// ─────────────────────────────────────────────

pub struct SecretKey {
    bytes: [u8; 32],
}

impl SecretKey {
    pub fn from_hex(hex: &str) -> Result<Self, CryptoError> {
        let bytes = hex_decode(hex)?;
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKey(
                format!("Expected 32 bytes, got {}", bytes.len())
            ));
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&bytes);
        Ok(SecretKey { bytes: key_bytes })
    }

    /// Generate a deterministic test key (NOT secure — demo only)
    pub fn test_key(seed: u64) -> Self {
        let mut bytes = [0u8; 32];
        let seed_bytes = seed.to_le_bytes();
        for i in 0..32 {
            bytes[i] = seed_bytes[i % 8].wrapping_add(i as u8).wrapping_mul(0x6b);
        }
        SecretKey { bytes }
    }

    pub fn public_key(&self) -> [u8; 33] {
        // Simplified pubkey derivation — production uses secp256k1::PublicKey
        let h = keccak256(&self.bytes);
        let mut pubkey = [0u8; 33];
        pubkey[0] = 0x02; // compressed, even y
        pubkey[1..].copy_from_slice(&h);
        pubkey
    }

    pub fn to_eth_address(&self) -> String {
        let pubkey = self.public_key();
        let hash = keccak256(&pubkey[1..]); // skip prefix byte
        // Last 20 bytes of the hash = Ethereum address
        format!("0x{}", hex_encode(&hash[12..]))
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        // Zero memory on drop — prevents key material from lingering
        self.bytes.iter_mut().for_each(|b| *b = 0);
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey([REDACTED])")
    }
}

// ─────────────────────────────────────────────
// TRANSACTION TYPES
// ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct UnsignedTransaction {
    pub nonce: u64,
    pub gas_price: u64,    // in gwei
    pub gas_limit: u64,
    pub to: String,
    pub value: u128,       // in wei
    pub data: Vec<u8>,
    pub chain_id: u64,     // 1 = mainnet, 137 = polygon
}

#[derive(Debug, Clone)]
pub struct SignedTransaction {
    pub hash: String,
    pub from: String,
    pub to: String,
    pub value_wei: u128,
    pub value_eth: f64,
    pub signature: Signature,
    pub raw: Vec<u8>,
    pub chain_id: u64,
    pub fee_gwei: u64,
    pub fee_usd: f64,
}

#[derive(Debug, Clone)]
pub struct Signature {
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub v: u8,
}

impl fmt::Display for SignedTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f,
            "SignedTx {{ hash: {}..{}, from: {}..{}, value: {:.6} ETH, fee: ${:.2} }}",
            &self.hash[..10], &self.hash[self.hash.len()-6..],
            &self.from[..10], &self.from[self.from.len()-6..],
            self.value_eth,
            self.fee_usd,
        )
    }
}

#[derive(Debug, Clone)]
pub struct BatchResult {
    pub signed: Vec<SignedTransaction>,
    pub failed: Vec<(usize, String)>,
    pub total_fee_usd: f64,
    pub duration: Duration,
}

// ─────────────────────────────────────────────
// CRYPTO ENGINE
// ─────────────────────────────────────────────

pub struct CryptoEngine {
    eth_price_usd: f64,
    chain_id: u64,
    tx_count: u64,
}

impl CryptoEngine {
    pub fn new(chain_id: u64, eth_price_usd: f64) -> Self {
        CryptoEngine {
            eth_price_usd,
            chain_id,
            tx_count: 0,
        }
    }

    /// Sign a single transaction
    pub fn sign(
        &mut self,
        tx: &UnsignedTransaction,
        key: &SecretKey,
    ) -> Result<SignedTransaction, CryptoError> {
        // Encode transaction fields for hashing
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&tx.nonce.to_le_bytes());
        encoded.extend_from_slice(&tx.gas_price.to_le_bytes());
        encoded.extend_from_slice(&tx.gas_limit.to_le_bytes());
        encoded.extend_from_slice(&tx.chain_id.to_le_bytes());

        if let Ok(to_bytes) = hex_decode(&tx.to) {
            encoded.extend_from_slice(&to_bytes);
        }

        let value_bytes: [u8; 16] = tx.value.to_le_bytes();
        encoded.extend_from_slice(&value_bytes);
        encoded.extend_from_slice(&tx.data);

        // Hash the encoded transaction (EIP-155 style)
        let tx_hash = keccak256(&encoded);

        // Sign: ECDSA over secp256k1 (simplified — production: secp256k1::sign)
        let r = keccak256(&[&key.bytes[..], &tx_hash[..]].concat());
        let s = keccak256(&[&tx_hash[..], &key.bytes[..]].concat());

        let signature = Signature {
            r,
            s,
            v: (self.chain_id * 2 + 35 + (tx_hash[0] & 1) as u64) as u8,
        };

        // Build raw transaction bytes
        let mut raw = encoded.clone();
        raw.extend_from_slice(&signature.r);
        raw.extend_from_slice(&signature.s);
        raw.push(signature.v);

        let final_hash = format!("0x{}", hex_encode(&keccak256(&raw)));
        let from_addr = key.to_eth_address();

        let fee_gwei = tx.gas_price * tx.gas_limit;
        let fee_eth = fee_gwei as f64 / 1e18;
        let fee_usd = fee_eth * self.eth_price_usd;

        self.tx_count += 1;

        Ok(SignedTransaction {
            hash: final_hash,
            from: from_addr,
            to: tx.to.clone(),
            value_wei: tx.value,
            value_eth: tx.value as f64 / 1e18,
            signature,
            raw,
            chain_id: tx.chain_id,
            fee_gwei,
            fee_usd,
        })
    }

    /// Sign multiple transactions in batch — processes concurrently in production
    pub fn sign_batch(
        &mut self,
        transactions: &[UnsignedTransaction],
        key: &SecretKey,
    ) -> BatchResult {
        let start = Instant::now();
        let mut signed = Vec::new();
        let mut failed = Vec::new();
        let mut total_fee = 0.0;

        for (i, tx) in transactions.iter().enumerate() {
            match self.sign(tx, key) {
                Ok(stx) => {
                    total_fee += stx.fee_usd;
                    signed.push(stx);
                }
                Err(e) => {
                    failed.push((i, e.to_string()));
                }
            }
        }

        BatchResult {
            signed,
            failed,
            total_fee_usd: total_fee,
            duration: start.elapsed(),
        }
    }

    /// Estimate gas for a transaction
    pub fn estimate_gas(&self, to: &str, value_wei: u128, data: &[u8]) -> u64 {
        let base_gas: u64 = 21_000;
        let data_gas: u64 = data.iter()
            .map(|&b| if b == 0 { 4u64 } else { 16u64 })
            .sum();
        // Contract interaction
        let contract_gas: u64 = if !data.is_empty() { 10_000 } else { 0 };
        base_gas + data_gas + contract_gas
    }

    /// Validate an Ethereum address
    pub fn validate_address(addr: &str) -> bool {
        let addr = addr.trim_start_matches("0x");
        addr.len() == 40 && addr.chars().all(|c| c.is_ascii_hexdigit())
    }

    pub fn tx_count(&self) -> u64 {
        self.tx_count
    }
}

// ─────────────────────────────────────────────
// HD WALLET KEY DERIVATION (BIP-32 simplified)
// ─────────────────────────────────────────────

pub struct HDWallet {
    master_key: SecretKey,
    derived_keys: HashMap<String, String>, // path -> address
}

impl HDWallet {
    pub fn from_seed(seed_hex: &str) -> Result<Self, CryptoError> {
        let key = SecretKey::from_hex(seed_hex)?;
        Ok(HDWallet {
            master_key: key,
            derived_keys: HashMap::new(),
        })
    }

    /// Derive a child key at path m/44'/60'/account'/0/index
    pub fn derive_address(&mut self, account: u32, index: u32) -> String {
        let path = format!("m/44'/60'/{}'/0/{}", account, index);

        if let Some(addr) = self.derived_keys.get(&path) {
            return addr.clone();
        }

        // Simplified derivation — production uses bip32 crate
        let mut data = Vec::new();
        data.extend_from_slice(&self.master_key.bytes);
        data.extend_from_slice(&account.to_le_bytes());
        data.extend_from_slice(&index.to_le_bytes());
        let derived = keccak256(&data);

        let child_key = SecretKey { bytes: derived };
        let address = child_key.to_eth_address();
        self.derived_keys.insert(path, address.clone());
        address
    }
}

// ─────────────────────────────────────────────
// MAIN / DEMO
// ─────────────────────────────────────────────

fn main() {
    println!("{}", "═".repeat(60));
    println!("  INTELLIX CRYPTO ENGINE — Rust 1.76");
    println!("{}", "═".repeat(60));

    let mut engine = CryptoEngine::new(137, 3502.18); // Polygon mainnet

    // Generate test keys
    println!("\n[1/4] Generating keys...");
    let key1 = SecretKey::test_key(0x_INTELLIX_01);
    let key2 = SecretKey::test_key(0x_INTELLIX_02);
    println!("  Key 1 → {}", key1.to_eth_address());
    println!("  Key 2 → {}", key2.to_eth_address());

    // Sign a single transaction
    println!("\n[2/4] Signing single transaction...");
    let tx = UnsignedTransaction {
        nonce: 42,
        gas_price: 30, // 30 gwei
        gas_limit: 21_000,
        to: "0x3f4a9b2c8e1d4f6a3b2c1d4e5f6a7b8c9d0e1f2a".to_string(),
        value: 1_500_000_000_000_000_000u128, // 1.5 ETH in wei
        data: vec![],
        chain_id: 137,
    };

    match engine.sign(&tx, &key1) {
        Ok(stx) => {
            println!("  {}", stx);
            println!("  Signature r: {}...", &hex_encode(&stx.signature.r)[..16]);
            println!("  Signature s: {}...", &hex_encode(&stx.signature.s)[..16]);
            println!("  v = {}", stx.signature.v);
        }
        Err(e) => eprintln!("  ✗ Error: {}", e),
    }

    // Batch sign
    println!("\n[3/4] Batch signing 5 transactions...");
    let batch: Vec<UnsignedTransaction> = (0..5).map(|i| UnsignedTransaction {
        nonce: i,
        gas_price: 20 + i * 2,
        gas_limit: 21_000,
        to: format!("0x{:040x}", i + 1),
        value: (i as u128 + 1) * 500_000_000_000_000_000u128, // 0.5–2.5 ETH
        data: vec![],
        chain_id: 137,
    }).collect();

    let start = Instant::now();
    let result = engine.sign_batch(&batch, &key1);
    let elapsed = start.elapsed();

    println!("  Signed  : {}", result.signed.len());
    println!("  Failed  : {}", result.failed.len());
    println!("  Total fee: ${:.4}", result.total_fee_usd);
    println!("  Duration: {:?}", elapsed);
    println!("  Throughput: {:.0} tx/sec",
        result.signed.len() as f64 / elapsed.as_secs_f64().max(0.000001));

    // HD wallet
    println!("\n[4/4] HD wallet key derivation (BIP-44)...");
    let seed = "a".repeat(64); // demo seed
    if let Ok(mut wallet) = HDWallet::from_seed(&seed) {
        for i in 0..4 {
            let addr = wallet.derive_address(0, i);
            println!("  m/44'/60'/0'/0/{} → {}", i, addr);
        }
    }

    // Gas estimation
    println!("\n[Gas estimates]");
    println!("  Simple ETH transfer   : {} gas", engine.estimate_gas("0xABCD", 1_000_000, &[]));
    println!("  ERC-20 transfer       : {} gas", engine.estimate_gas("0xABCD", 0, &[0u8; 68]));
    println!("  Contract interaction  : {} gas", engine.estimate_gas("0xABCD", 0, &[0xau8; 200]));

    println!("\n  Total txns signed this session: {}", engine.tx_count());
}
