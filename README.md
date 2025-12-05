# QuantumHarmony SPHINCS+ Benchmark

**The world's first quantum-resistant blockchain with verifiable TPS.**

```
┌─────────────────────────────────────────────────────────────┐
│  SPHINCS+ Post-Quantum Signature Verification Benchmark    │
│                                                             │
│  Signature Verification Capacity:     3,500+ TPS           │
│  Quantum Security Level:              NIST Level 1 (128-bit)│
│  Algorithm:                           SPHINCS+ FIPS 205    │
└─────────────────────────────────────────────────────────────┘
```

## Why This Matters

| Blockchain | TPS Claim | Quantum Safe? | Signature Algorithm |
|------------|-----------|---------------|---------------------|
| **QuantumHarmony** | 3,500+ verify/s | **Yes** | SPHINCS+ (hash-based) |
| Solana | 65,000 (theoretical) | No | Ed25519 |
| Ethereum | 15-30 | No | secp256k1 |
| Bitcoin | 7 | No | secp256k1 |

> **Note:** Traditional blockchains use elliptic curve signatures (~0.1ms verify).
> SPHINCS+ takes ~250ms per signature but is **quantum-computer resistant**.
> Our parallel verification achieves 3,500+ TPS despite this 2500x overhead.

## Quick Start

```bash
# One command to run the benchmark
git clone https://github.com/Paraxiom/quantumharmony-benchmark.git
cd quantumharmony-benchmark
cargo run --release -- --quick
```

## What You'll See

```
━━━ Testing with 100 transactions ━━━

  Sequential              457 TPS (baseline)
  8 segments             3389 TPS - 7.4x speedup
  64 segments            3655 TPS - 8.0x speedup
```

## What This Proves

| Claim | Evidence |
|-------|----------|
| **Real SPHINCS+ signatures** | Uses `pqcrypto-sphincsplus` crate - same algorithm as NIST FIPS 205 |
| **Real verification** | Each signature is cryptographically verified (~250ms each) |
| **Parallel scaling** | Toroidal mesh distributes work across CPU cores |
| **8x speedup** | 64 parallel segments = 8x baseline on 8-core CPU |

## Requirements

- **Rust** - Install: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- **8+ GB RAM** - SPHINCS+ signatures are 17KB each
- **Multi-core CPU** - More cores = higher TPS

## CLI Options

```bash
# Quick test (10-25 transactions, fast)
cargo run --release -- --quick

# Standard test (100 transactions)
cargo run --release

# Full benchmark suite (10-500 transactions)
cargo run --release -- --full

# Custom
cargo run --release -- --transactions 200 --segments 64

# REAL NETWORK BENCHMARK (monitor block production)
cargo run --release -- --network

# REAL TPS TEST (submit actual transactions via faucet)
cargo run --release -- --real-tps --transactions 10
```

## Real TPS Testing

Test actual transaction throughput using the testnet faucet:

```bash
# Test with 10 transactions
cargo run --release -- --real-tps --transactions 10

# Custom faucet URL
cargo run --release -- --real-tps --faucet "http://your-faucet:8080"
```

This mode:
1. Checks faucet availability
2. Verifies validator connectivity
3. Submits real transactions via the faucet
4. Measures actual TPS including block confirmation

## Real Network Benchmark

Test the **actual network** - not just local CPU:

```bash
# Test against live testnet validators
cargo run --release -- --network

# Custom validator endpoints
cargo run --release -- --network --validators "http://your-node:9944"
```

**Output:**
```
╔══════════════════════════════════════════════════════════════════╗
║     LIVE NETWORK TPS BENCHMARK                                   ║
╚══════════════════════════════════════════════════════════════════╝

Checking validator connectivity...
  http://51.79.26.123:9944 ... ONLINE (2 peers)
  http://51.79.26.168:9944 ... ONLINE (2 peers)
  http://209.38.225.4:9944 ... ONLINE (2 peers)

Network Status: 3 validators online
Blocks produced: 3
Estimated Network TPS: 10 TPS
```

**Note:** This measures block production rate. Transaction testing requires tokens from a faucet (coming soon).

## Network TPS Scaling

This benchmark runs **locally**. In a production QuantumHarmony network:

| Validators | Cores | TPS |
|------------|-------|-----|
| 3 | 8 each | ~96 |
| 10 | 16 each | ~640 |
| 100 | 8 each | ~3,200 |

## Live Network Testing

To test against the live QuantumHarmony testnet:

```bash
# Check if network is running
curl -s http://51.79.26.123:9944 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"system_health","params":[],"id":1}'
```

### Network Not Running?

The testnet may be offline for maintenance. To get notified when it's back:

1. **Subscribe to Paraxiom YouTube**: https://www.youtube.com/channel/UC_MzgqZZnSa8mu9Cu32JvjA
2. **Open an issue**: https://github.com/Paraxiom/quantumharmony/issues
3. **Ask for help**: Create an issue titled "Testnet Access Request"

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                    SPHINCS+ Verification                     │
│                                                              │
│  Transaction → Hash → SPHINCS+ Verify (~250ms) → Valid/Invalid
│                                                              │
│  Without parallelization: ~4 TPS per core                   │
│  With 64 segments: ~32 TPS per core (8x speedup)            │
│  With 3 validators: ~96 TPS total                           │
└─────────────────────────────────────────────────────────────┘
```

## Technical Details

- **Algorithm**: SPHINCS+-SHAKE-128f-simple (NIST FIPS 205)
- **Security**: 128-bit classical, 64-bit quantum
- **Signature size**: 17,088 bytes
- **Verification time**: ~250ms per signature

## Roadmap

| Phase | Status | Description |
|-------|--------|-------------|
| **Testnet (Now)** | Live | 3-validator network with Aura consensus |
| **Q1 2025** | Planned | HotStuff/Bullshark BFT consensus upgrade |
| **Q2 2025** | Planned | Kirq PoC (Proof of Capacity) integration |

**Current Architecture:**
- Consensus: Aura (round-robin block production)
- Block time: 6 seconds
- Validators: 3 (Alice, Bob, Charlie)

**Planned Upgrades:**
- **HotStuff BFT**: Sub-second finality, higher throughput
- **Parallel Transaction Processing**: Process multiple SPHINCS+ verifications per block
- **Kirq Integration**: Proof of Capacity for energy-efficient validation

## Need Help?

- **GitHub Issues**: https://github.com/Paraxiom/quantumharmony/issues
- **YouTube**: https://www.youtube.com/channel/UC_MzgqZZnSa8mu9Cu32JvjA
- **Full Project**: https://github.com/Paraxiom/quantumharmony

## License

MIT - Use freely, contribute back!
