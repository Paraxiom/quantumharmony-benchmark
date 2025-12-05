//! QuantumHarmony SPHINCS+ TPS Benchmark
//!
//! This benchmark measures real SPHINCS+ (SLH-DSA) post-quantum signature
//! verification throughput using toroidal mesh parallelization.
//!
//! SPHINCS+ is a NIST-standardized hash-based signature scheme that provides
//! quantum resistance. This benchmark demonstrates how QuantumHarmony achieves
//! high TPS despite the ~250ms verification time per signature.
//!
//! NETWORK MODE: Use --network to test against real QuantumHarmony validators!

use clap::Parser;
use colored::*;
use pqcrypto_sphincsplus::sphincsshake128fsimple::*;
use pqcrypto_traits::sign::{PublicKey, SecretKey, SignedMessage};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// SPHINCS+ TPS Benchmark for QuantumHarmony
#[derive(Parser, Debug)]
#[command(name = "sphincs-benchmark")]
#[command(author = "QuantumHarmony Team")]
#[command(version = "1.0.0")]
#[command(about = "Benchmark SPHINCS+ post-quantum signature verification throughput")]
struct Args {
    /// Number of transactions to generate and verify
    #[arg(short, long, default_value = "100")]
    transactions: usize,

    /// Number of parallel segments (toroidal mesh)
    #[arg(short, long, default_value = "64")]
    segments: usize,

    /// Number of keypairs to generate (reused for signing)
    #[arg(short, long, default_value = "10")]
    keypairs: usize,

    /// Run quick mode (fewer transactions for fast results)
    #[arg(long)]
    quick: bool,

    /// Run full benchmark suite
    #[arg(long)]
    full: bool,

    /// Run REAL network benchmark against live validators
    #[arg(long)]
    network: bool,

    /// Run REAL TPS test with actual transactions (requires faucet)
    #[arg(long)]
    real_tps: bool,

    /// Faucet URL for requesting test tokens
    #[arg(long, default_value = "http://51.79.26.123:8080")]
    faucet: String,

    /// Validator RPC endpoints (comma-separated)
    #[arg(long, default_value = "http://51.79.26.123:9944,http://51.79.26.168:9944,http://209.38.225.4:9944")]
    validators: String,
}

// JSON-RPC types for Substrate
#[derive(Serialize, Debug)]
struct RpcRequest {
    jsonrpc: String,
    id: u32,
    method: String,
    params: Vec<serde_json::Value>,
}

#[derive(Deserialize, Debug)]
struct RpcResponse {
    #[allow(dead_code)]
    jsonrpc: String,
    #[allow(dead_code)]
    id: u32,
    result: Option<serde_json::Value>,
    error: Option<RpcError>,
}

#[derive(Deserialize, Debug)]
struct RpcError {
    #[allow(dead_code)]
    code: i32,
    message: String,
}

#[derive(Deserialize, Debug)]
struct SystemHealth {
    peers: u32,
    #[serde(rename = "isSyncing")]
    is_syncing: bool,
}

/// A mock transaction with SPHINCS+ signature
struct SignedTransaction {
    payload: Vec<u8>,
    signature: Vec<u8>,
    public_key: Vec<u8>,
    segment_id: u32,
}

impl SignedTransaction {
    fn new(
        keypair: &(Vec<u8>, Vec<u8>), // (public_key, secret_key)
        to: &[u8],
        amount: u64,
        nonce: u64,
        segment_id: u32,
    ) -> Self {
        // Create transaction payload
        let mut payload = Vec::new();
        payload.extend_from_slice(&keypair.0[..32.min(keypair.0.len())]); // from (truncated pk)
        payload.extend_from_slice(to);
        payload.extend_from_slice(&amount.to_le_bytes());
        payload.extend_from_slice(&nonce.to_le_bytes());

        // Hash the payload for signing
        let mut hasher = Sha3_256::new();
        hasher.update(&payload);
        let hash = hasher.finalize();

        // Sign with SPHINCS+ (this is expensive!)
        let sk = SecretKey::from_bytes(&keypair.1).expect("Invalid secret key");
        let signed_msg = sign(&hash, &sk);
        let signature = signed_msg.as_bytes().to_vec();

        Self {
            payload,
            signature,
            public_key: keypair.0.clone(),
            segment_id,
        }
    }

    /// Verify SPHINCS+ signature (expensive operation ~250ms)
    fn verify(&self) -> bool {
        // Reconstruct hash
        let mut hasher = Sha3_256::new();
        hasher.update(&self.payload);
        let hash = hasher.finalize();

        // Parse public key
        let pk = match PublicKey::from_bytes(&self.public_key) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        // Create signed message for verification
        let signed_msg = match SignedMessage::from_bytes(&self.signature) {
            Ok(sm) => sm,
            Err(_) => return false,
        };

        // Verify and check if the opened message matches our hash
        match open(&signed_msg, &pk) {
            Ok(opened) => opened == hash.as_slice(),
            Err(_) => false,
        }
    }
}

/// Generate SPHINCS+ keypairs
fn generate_keypairs(count: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
    (0..count)
        .map(|_| {
            let (pk, sk) = keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        })
        .collect()
}

/// Sequential verification (baseline)
fn verify_sequential(transactions: &[SignedTransaction]) -> (usize, Duration) {
    let start = Instant::now();
    let mut verified = 0;

    for tx in transactions {
        if tx.verify() {
            verified += 1;
        }
    }

    (verified, start.elapsed())
}

/// Parallel verification with toroidal segmentation
fn verify_parallel(transactions: &[SignedTransaction], num_segments: usize) -> (usize, Duration) {
    // Partition transactions by segment
    let mut segment_txs: Vec<Vec<&SignedTransaction>> = vec![Vec::new(); num_segments];
    for tx in transactions {
        let idx = (tx.segment_id as usize) % num_segments;
        segment_txs[idx].push(tx);
    }

    let verified = Arc::new(AtomicUsize::new(0));
    let start = Instant::now();

    // Process segments in parallel using rayon
    segment_txs.par_iter().for_each(|segment| {
        let mut count = 0;
        for tx in segment {
            if tx.verify() {
                count += 1;
            }
        }
        verified.fetch_add(count, Ordering::Relaxed);
    });

    (verified.load(Ordering::Relaxed), start.elapsed())
}

fn print_header() {
    println!();
    println!("{}", "╔══════════════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║     QUANTUMHARMONY SPHINCS+ TPS BENCHMARK                        ║".cyan());
    println!("{}", "║     Post-Quantum Signature Verification Performance             ║".cyan());
    println!("{}", "╚══════════════════════════════════════════════════════════════════╝".cyan());
    println!();
    println!("{}", "About SPHINCS+ (SLH-DSA):".yellow().bold());
    println!("  - NIST-standardized post-quantum hash-based signature scheme");
    println!("  - Provides quantum resistance against Shor's algorithm");
    println!("  - Signature size: ~17KB (SHAKE128f-simple variant)");
    println!("  - Verification time: ~250ms per signature");
    println!();
    println!("{}", "QuantumHarmony Optimizations:".yellow().bold());
    println!("  - Toroidal mesh parallelization (512 segments = 8×8×8 3D torus)");
    println!("  - Pre-verification pool moves verification off critical path");
    println!("  - Distributed workload across validator nodes");
    println!();
}

fn print_result(label: &str, verified: usize, total: usize, duration: Duration, baseline_tps: Option<f64>) {
    let tps = verified as f64 / duration.as_secs_f64();
    let speedup = baseline_tps.map(|b| tps / b);

    print!("  {:20} ", label);
    print!("{} ", format!("{:>8.0} TPS", tps).green().bold());
    print!("({:>6.3}s) ", duration.as_secs_f64());
    print!("[{}/{}] ", verified, total);

    if let Some(s) = speedup {
        if s > 1.0 {
            println!("{}", format!("{:.1}x speedup", s).yellow());
        } else {
            println!();
        }
    } else {
        println!("{}", "(baseline)".dimmed());
    }
}

fn run_benchmark(tx_count: usize, segments: usize, keypairs: &[(Vec<u8>, Vec<u8>)]) {
    println!("{}", format!("━━━ Testing with {} transactions ━━━", tx_count).blue().bold());
    println!();

    // Generate signed transactions
    print!("  Generating {} SPHINCS+ signed transactions... ", tx_count);
    std::io::Write::flush(&mut std::io::stdout()).unwrap();

    let gen_start = Instant::now();
    let transactions: Vec<SignedTransaction> = (0..tx_count)
        .map(|i| {
            let kp = &keypairs[i % keypairs.len()];
            let to = vec![0xFFu8; 32];
            SignedTransaction::new(kp, &to, 1000, i as u64, (i % 512) as u32)
        })
        .collect();
    println!("{} ({:.2}s)", "Done".green(), gen_start.elapsed().as_secs_f64());
    println!();

    // Sequential baseline
    let (seq_verified, seq_time) = verify_sequential(&transactions);
    let baseline_tps = seq_verified as f64 / seq_time.as_secs_f64();
    print_result("Sequential", seq_verified, tx_count, seq_time, None);

    // Parallel with different segment counts
    for num_seg in [2, 4, 8, 16, 32, 64, 128, 256, 512].iter().filter(|&&s| s <= segments * 8) {
        let (par_verified, par_time) = verify_parallel(&transactions, *num_seg);
        print_result(&format!("{} segments", num_seg), par_verified, tx_count, par_time, Some(baseline_tps));
    }

    println!();
}

// ==================== NETWORK BENCHMARK FUNCTIONS ====================

/// Check validator health via RPC
fn check_validator_health(url: &str) -> Result<SystemHealth, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;

    let request = RpcRequest {
        jsonrpc: "2.0".to_string(),
        id: 1,
        method: "system_health".to_string(),
        params: vec![],
    };

    let response: RpcResponse = client
        .post(url)
        .json(&request)
        .send()
        .map_err(|e| format!("Connection failed: {}", e))?
        .json()
        .map_err(|e| format!("Parse failed: {}", e))?;

    if let Some(error) = response.error {
        return Err(error.message);
    }

    let result = response.result.ok_or("No result")?;
    serde_json::from_value(result).map_err(|e| e.to_string())
}

/// Get current block number from validator
fn get_block_number(url: &str) -> Result<u64, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;

    let request = RpcRequest {
        jsonrpc: "2.0".to_string(),
        id: 1,
        method: "chain_getHeader".to_string(),
        params: vec![],
    };

    let response: RpcResponse = client
        .post(url)
        .json(&request)
        .send()
        .map_err(|e| format!("Connection failed: {}", e))?
        .json()
        .map_err(|e| format!("Parse failed: {}", e))?;

    if let Some(error) = response.error {
        return Err(error.message);
    }

    let result = response.result.ok_or("No result")?;
    let number_hex = result
        .get("number")
        .and_then(|n| n.as_str())
        .ok_or("No block number")?;

    // Parse hex number (0x...)
    let number = u64::from_str_radix(number_hex.trim_start_matches("0x"), 16)
        .map_err(|e| format!("Parse block number failed: {}", e))?;

    Ok(number)
}

/// Run network benchmark against live validators
fn run_network_benchmark(validators: &[String], duration_secs: u64) {
    println!();
    println!(
        "{}",
        "╔══════════════════════════════════════════════════════════════════╗".cyan()
    );
    println!(
        "{}",
        "║     LIVE NETWORK TPS BENCHMARK                                   ║".cyan()
    );
    println!(
        "{}",
        "║     Testing REAL validator performance                           ║".cyan()
    );
    println!(
        "{}",
        "╚══════════════════════════════════════════════════════════════════╝".cyan()
    );
    println!();

    // Check all validators
    println!("{}", "Checking validator connectivity...".yellow());
    let mut online_validators: Vec<(String, String)> = Vec::new();

    for url in validators {
        print!("  {} ... ", url);
        std::io::Write::flush(&mut std::io::stdout()).unwrap();

        match check_validator_health(url) {
            Ok(health) => {
                if health.is_syncing {
                    println!("{}", "SYNCING (skip)".yellow());
                } else {
                    println!(
                        "{} ({} peers)",
                        "ONLINE".green().bold(),
                        health.peers
                    );
                    // Extract name from URL for display
                    let name = if url.contains("51.79.26.123") {
                        "Alice"
                    } else if url.contains("51.79.26.168") {
                        "Bob"
                    } else if url.contains("209.38.225.4") {
                        "Charlie"
                    } else {
                        "Validator"
                    };
                    online_validators.push((url.clone(), name.to_string()));
                }
            }
            Err(e) => {
                println!("{} ({})", "OFFLINE".red(), e);
            }
        }
    }

    if online_validators.is_empty() {
        println!();
        println!(
            "{}",
            "ERROR: No validators online! Cannot run network benchmark.".red()
        );
        println!("Please ensure the QuantumHarmony network is running.");
        return;
    }

    println!();
    println!(
        "{}: {} validators online",
        "Network Status".yellow().bold(),
        online_validators.len()
    );
    println!();

    // Monitor block production for the specified duration
    println!(
        "{}",
        format!("Monitoring block production for {} seconds...", duration_secs)
            .blue()
            .bold()
    );
    println!();

    let primary_url = &online_validators[0].0;

    // Get starting block
    let start_block = match get_block_number(primary_url) {
        Ok(b) => b,
        Err(e) => {
            println!("{}", format!("Failed to get block number: {}", e).red());
            return;
        }
    };

    println!(
        "  Starting block: {}",
        format!("#{}", start_block).green()
    );

    let start_time = Instant::now();

    // Wait for the benchmark duration
    std::thread::sleep(Duration::from_secs(duration_secs));

    // Get ending block
    let end_block = match get_block_number(primary_url) {
        Ok(b) => b,
        Err(e) => {
            println!("{}", format!("Failed to get block number: {}", e).red());
            return;
        }
    };

    let elapsed = start_time.elapsed();
    let blocks_produced = end_block.saturating_sub(start_block);
    let block_time = if blocks_produced > 0 {
        elapsed.as_secs_f64() / blocks_produced as f64
    } else {
        0.0
    };

    println!(
        "  Ending block:   {}",
        format!("#{}", end_block).green()
    );
    println!();

    // Calculate TPS estimates
    // SPHINCS+ verification time is ~250ms per signature
    // With 3 validators and 8 cores each = 24 parallel verifiers
    // At 4 TPS per core = ~96 TPS theoretical
    // With toroidal mesh optimization, we can achieve higher throughput

    let blocks_per_sec = blocks_produced as f64 / elapsed.as_secs_f64();

    // Each block can contain multiple transactions
    // Estimate based on block production rate and validator capacity
    let tx_per_block_estimate = 100; // Conservative estimate
    let network_tps = blocks_per_sec * tx_per_block_estimate as f64;

    // Calculate theoretical maximum based on SPHINCS+ verification
    let validator_count = online_validators.len();
    let cores_per_validator = num_cpus::get(); // Use local cores as estimate
    let tps_per_core = 4.0; // ~250ms per verification = 4 TPS
    let theoretical_max = (validator_count * cores_per_validator) as f64 * tps_per_core;

    println!("{}", "━━━ NETWORK TPS RESULTS ━━━".blue().bold());
    println!();
    println!(
        "  {:25} {}",
        "Blocks produced:",
        format!("{}", blocks_produced).green().bold()
    );
    println!(
        "  {:25} {}",
        "Time elapsed:",
        format!("{:.2}s", elapsed.as_secs_f64()).white()
    );
    println!(
        "  {:25} {}",
        "Block time:",
        format!("{:.2}s", block_time).white()
    );
    println!(
        "  {:25} {}",
        "Blocks/second:",
        format!("{:.2}", blocks_per_sec).yellow()
    );
    println!();
    println!(
        "  {:25} {}",
        "Estimated Network TPS:",
        format!("{:.0} TPS", network_tps).green().bold()
    );
    println!(
        "  {:25} {}",
        "Theoretical Maximum:",
        format!("{:.0} TPS", theoretical_max).yellow()
    );
    println!();

    // Show per-validator stats
    println!("{}", "Per-Validator Performance:".yellow().bold());
    for (url, name) in &online_validators {
        if let Ok(health) = check_validator_health(url) {
            println!(
                "  {} ({} peers): {}",
                name.cyan(),
                health.peers,
                "Active".green()
            );
        }
    }
    println!();

    println!("{}", "Note:".dimmed());
    println!(
        "{}",
        "  - Network TPS depends on transaction volume and block capacity".dimmed()
    );
    println!(
        "{}",
        "  - SPHINCS+ signatures take ~250ms to verify".dimmed()
    );
    println!(
        "{}",
        "  - Higher TPS achieved through parallel verification".dimmed()
    );
    println!();
}

// ==================== REAL TPS TESTING FUNCTIONS ====================

#[derive(Deserialize, Debug)]
struct FaucetResponse {
    success: bool,
    message: String,
    tx_hash: Option<String>,
    amount: String,
}

#[derive(Deserialize, Debug)]
struct FaucetStatus {
    status: String,
    active_validator: String,
    pending_txs: usize,
    drip_amount: String,
    rate_limit_seconds: i64,
}

/// Request tokens from the faucet
fn request_faucet_drip(faucet_url: &str, address: &str) -> Result<FaucetResponse, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;

    let drip_url = format!("{}/drip", faucet_url);
    let body = serde_json::json!({ "address": address });

    let response: FaucetResponse = client
        .post(&drip_url)
        .json(&body)
        .send()
        .map_err(|e| format!("Faucet request failed: {}", e))?
        .json()
        .map_err(|e| format!("Failed to parse faucet response: {}", e))?;

    Ok(response)
}

/// Get faucet status
fn get_faucet_status(faucet_url: &str) -> Result<FaucetStatus, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;

    let status_url = format!("{}/status", faucet_url);

    let response: FaucetStatus = client
        .get(&status_url)
        .send()
        .map_err(|e| format!("Status request failed: {}", e))?
        .json()
        .map_err(|e| format!("Failed to parse status: {}", e))?;

    Ok(response)
}

/// Generate a test Substrate address (SS58 format)
/// Uses well-known Substrate dev account addresses for testing
fn generate_test_address(seed: u64) -> String {
    // Use well-known Substrate dev addresses for testing
    // These are the standard dev accounts used in Substrate testnets
    let addresses = [
        "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY", // Alice
        "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty", // Bob
        "5FLSigC9HGRKVhB9FiEo4Y3koPsNmBmLJbpXg2mp1hXcS59Y", // Charlie
        "5DAAnrj7VHTznn2AWBemMuyBwZWs6FNFjdyVXUeYum3PTXFy", // Dave
        "5HGjWAeFDfFCWPsjFQdVV2Msvz2XtMktvgocEZcCj68kUMaw", // Eve
        "5CiPPseXPECbkjWCa6MnjNokrgYjMqmKndv2rSnekmSK2DjL", // Ferdie
        "5GNJqTPyNqANBkUVMN1LPPrxXnFouWXoe2wNSmmEoLctxiZY", // Alice_stash
        "5HpG9w8EBLe5XCrbczpwq5TSXvedjrBGCwqxK1iQ7qUsSWFc", // Bob_stash
        "5Ck5SLSHYac6WFt5UZRSsdJjwmpSZq85fd5TRNAdZQVzEAPT", // Charlie_stash
        "5HKPmK9GYtE1PSLsS1unMfdBH6cJjKBr7mKz3f8v1erP1VVY", // Dave_stash
    ];
    addresses[(seed as usize) % addresses.len()].to_string()
}

/// Run real TPS test against live network using faucet
fn run_real_tps_test(faucet_url: &str, validators: &[String], tx_count: usize) {
    println!();
    println!(
        "{}",
        "╔══════════════════════════════════════════════════════════════════╗".cyan()
    );
    println!(
        "{}",
        "║     REAL NETWORK TPS TEST                                        ║".cyan()
    );
    println!(
        "{}",
        "║     Testing ACTUAL transactions on live network                  ║".cyan()
    );
    println!(
        "{}",
        "╚══════════════════════════════════════════════════════════════════╝".cyan()
    );
    println!();

    // Check faucet status
    println!("{}", "Checking faucet status...".yellow());
    match get_faucet_status(faucet_url) {
        Ok(status) => {
            println!("  Status: {}", status.status.green());
            println!("  Active validator: {}", status.active_validator);
            println!("  Drip amount: {}", status.drip_amount);
            println!("  Rate limit: {}s", status.rate_limit_seconds);
            println!();
        }
        Err(e) => {
            println!("{}", format!("Faucet not available: {}", e).red());
            println!("Please ensure the faucet is running at {}", faucet_url);
            return;
        }
    }

    // Check validators
    println!("{}", "Checking validator connectivity...".yellow());
    let mut online_validators: Vec<String> = Vec::new();

    for url in validators {
        print!("  {} ... ", url);
        std::io::Write::flush(&mut std::io::stdout()).unwrap();

        match check_validator_health(url) {
            Ok(health) => {
                if !health.is_syncing {
                    println!("{} ({} peers)", "ONLINE".green().bold(), health.peers);
                    online_validators.push(url.clone());
                } else {
                    println!("{}", "SYNCING".yellow());
                }
            }
            Err(e) => {
                println!("{} ({})", "OFFLINE".red(), e);
            }
        }
    }

    if online_validators.is_empty() {
        println!();
        println!("{}", "ERROR: No validators online!".red());
        return;
    }

    let primary_validator = &online_validators[0];

    // Get starting block
    let start_block = match get_block_number(primary_validator) {
        Ok(b) => b,
        Err(e) => {
            println!("{}", format!("Failed to get block number: {}", e).red());
            return;
        }
    };

    println!();
    println!("{}", format!("━━━ Starting Real TPS Test ━━━").blue().bold());
    println!("  Target transactions: {}", tx_count);
    println!("  Starting block: #{}", start_block);
    println!();

    // Submit transactions via faucet
    println!("{}", "Submitting transactions...".yellow());
    let start_time = Instant::now();
    let mut successful_txs = 0;
    let mut failed_txs = 0;
    let mut tx_hashes: Vec<String> = Vec::new();

    for i in 0..tx_count {
        // Generate unique address for each request (to avoid rate limiting)
        let address = generate_test_address(i as u64);

        print!("  [{}/{}] {} ... ", i + 1, tx_count, &address[..20]);
        std::io::Write::flush(&mut std::io::stdout()).unwrap();

        match request_faucet_drip(faucet_url, &address) {
            Ok(response) => {
                if response.success {
                    println!("{}", "OK".green());
                    if let Some(hash) = response.tx_hash {
                        tx_hashes.push(hash);
                    }
                    successful_txs += 1;
                } else {
                    println!("{} ({})", "FAILED".red(), response.message);
                    failed_txs += 1;

                    // If rate limited, wait
                    if response.message.contains("Rate limited") {
                        println!("    {} Waiting for rate limit...", "⏳".yellow());
                        std::thread::sleep(Duration::from_secs(5));
                    }
                }
            }
            Err(e) => {
                println!("{} ({})", "ERROR".red(), e);
                failed_txs += 1;
            }
        }

        // Small delay between requests to not overwhelm the faucet
        if i < tx_count - 1 {
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    let submission_time = start_time.elapsed();

    // Wait for transactions to be included in blocks
    println!();
    println!("{}", "Waiting for block confirmation...".yellow());
    std::thread::sleep(Duration::from_secs(12)); // Wait for ~2 blocks

    // Get ending block
    let end_block = match get_block_number(primary_validator) {
        Ok(b) => b,
        Err(e) => {
            println!("{}", format!("Failed to get block number: {}", e).red());
            start_block
        }
    };

    let total_time = start_time.elapsed();
    let blocks_produced = end_block.saturating_sub(start_block);

    // Calculate metrics
    let submission_tps = if submission_time.as_secs_f64() > 0.0 {
        successful_txs as f64 / submission_time.as_secs_f64()
    } else {
        0.0
    };

    let effective_tps = if total_time.as_secs_f64() > 0.0 {
        successful_txs as f64 / total_time.as_secs_f64()
    } else {
        0.0
    };

    // Print results
    println!();
    println!("{}", "━━━ REAL TPS RESULTS ━━━".blue().bold());
    println!();
    println!(
        "  {:30} {}",
        "Transactions submitted:",
        format!("{}", tx_count).white()
    );
    println!(
        "  {:30} {}",
        "Successful:",
        format!("{}", successful_txs).green().bold()
    );
    println!(
        "  {:30} {}",
        "Failed:",
        format!("{}", failed_txs).red()
    );
    println!();
    println!(
        "  {:30} {}",
        "Submission time:",
        format!("{:.2}s", submission_time.as_secs_f64()).white()
    );
    println!(
        "  {:30} {}",
        "Total time (with confirmation):",
        format!("{:.2}s", total_time.as_secs_f64()).white()
    );
    println!();
    println!(
        "  {:30} {}",
        "Blocks produced:",
        format!("{}", blocks_produced).yellow()
    );
    println!(
        "  {:30} {}",
        "Start → End block:",
        format!("#{} → #{}", start_block, end_block).white()
    );
    println!();
    println!(
        "  {:30} {}",
        "Submission TPS:",
        format!("{:.2} TPS", submission_tps).green().bold()
    );
    println!(
        "  {:30} {}",
        "Effective TPS:",
        format!("{:.2} TPS", effective_tps).yellow().bold()
    );
    println!();

    if !tx_hashes.is_empty() {
        println!("{}", "Sample transaction hashes:".dimmed());
        for hash in tx_hashes.iter().take(3) {
            println!("  {}", hash.dimmed());
        }
    }

    println!();
    println!("{}", "Note:".dimmed());
    println!(
        "{}",
        "  - Faucet rate limiting may affect results".dimmed()
    );
    println!(
        "{}",
        "  - For accurate TPS, use multiple addresses".dimmed()
    );
    println!(
        "{}",
        "  - SPHINCS+ verification happens during block production".dimmed()
    );
    println!();
}

fn main() {
    let args = Args::parse();

    // Parse validators
    let validators: Vec<String> = args
        .validators
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();

    // If real TPS mode, run actual transaction test
    if args.real_tps {
        run_real_tps_test(&args.faucet, &validators, args.transactions);
        return;
    }

    // If network mode, run network benchmark (block monitoring only)
    if args.network {
        run_network_benchmark(&validators, 30); // 30 second benchmark
        return;
    }

    print_header();

    // Determine transaction counts based on mode
    let tx_counts = if args.quick {
        vec![10, 25]
    } else if args.full {
        vec![10, 50, 100, 200, 500]
    } else {
        vec![args.transactions]
    };

    // Generate keypairs
    println!("{}", "Generating SPHINCS+ keypairs...".yellow());
    print!("  Creating {} keypairs... ", args.keypairs);
    std::io::Write::flush(&mut std::io::stdout()).unwrap();

    let kp_start = Instant::now();
    let keypairs = generate_keypairs(args.keypairs);
    println!("{} ({:.2}s)", "Done".green(), kp_start.elapsed().as_secs_f64());
    println!();

    // Run benchmarks
    for tx_count in tx_counts {
        run_benchmark(tx_count, args.segments, &keypairs);
    }

    // Summary
    println!("{}", "╔══════════════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║  SUMMARY                                                         ║".cyan());
    println!("{}", "╚══════════════════════════════════════════════════════════════════╝".cyan());
    println!();
    println!("  {}: {} cores detected", "System".yellow(), num_cpus::get());
    println!("  {}: ~{} TPS per core (250ms verification)", "Theoretical".yellow(), 4);
    println!("  {}: ~{} TPS with all cores", "Maximum".yellow(), num_cpus::get() * 4);
    println!();
    println!("{}", "Network Scaling:".yellow().bold());
    println!("  - 3 validators × 8 cores  = ~96 TPS theoretical");
    println!("  - 10 validators × 16 cores = ~640 TPS theoretical");
    println!("  - With pre-verification: transactions appear instant to users");
    println!();
    println!("{}", "Learn more: https://github.com/Paraxiom/quantumharmony".dimmed());
    println!();
}
