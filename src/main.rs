//! QuantumHarmony SPHINCS+ TPS Benchmark
//!
//! This benchmark measures real SPHINCS+ (SLH-DSA) post-quantum signature
//! verification throughput using toroidal mesh parallelization.
//!
//! SPHINCS+ is a NIST-standardized hash-based signature scheme that provides
//! quantum resistance. This benchmark demonstrates how QuantumHarmony achieves
//! high TPS despite the ~250ms verification time per signature.

use clap::Parser;
use colored::*;
use pqcrypto_sphincsplus::sphincsshake128fsimple::*;
use pqcrypto_traits::sign::{PublicKey, SecretKey, SignedMessage};
use rayon::prelude::*;
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
    print!("{:>8.0} TPS ", tps.to_string().green().bold());
    print!("({:>6.3}s) ", duration.as_secs_f64());
    print!("[{}/{}] ", verified, total);

    if let Some(s) = speedup {
        if s > 1.0 {
            println!("{}", format!("{:.2}x speedup", s).yellow());
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

fn main() {
    let args = Args::parse();

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
