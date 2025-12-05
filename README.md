# QuantumHarmony SPHINCS+ Benchmark

**Verify quantum-resistant signature performance yourself.**

```
┌─────────────────────────────────────────────────────────────┐
│  SPHINCS+ Post-Quantum Signature Verification Benchmark    │
│  Proves: 3,500+ TPS with quantum-safe cryptography         │
└─────────────────────────────────────────────────────────────┘
```

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
```

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

1. **Subscribe to Paraxiom YouTube**: https://www.youtube.com/@Paraxiom
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

## Need Help?

- **GitHub Issues**: https://github.com/Paraxiom/quantumharmony/issues
- **YouTube**: https://www.youtube.com/@Paraxiom
- **Full Project**: https://github.com/Paraxiom/quantumharmony

## License

MIT - Use freely, contribute back!
