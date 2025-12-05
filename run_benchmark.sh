#!/bin/bash
# QuantumHarmony SPHINCS+ TPS Benchmark Runner
# One-click script to run the benchmark

set -e

echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║     QUANTUMHARMONY SPHINCS+ TPS BENCHMARK                        ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

# Check if Rust is installed
if ! command -v cargo &> /dev/null; then
    echo "Rust not found. Installing..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

echo "Building benchmark (release mode)..."
cargo build --release

echo ""
echo "Running benchmark..."
echo ""

# Run with provided arguments or default to quick mode
if [ $# -eq 0 ]; then
    ./target/release/sphincs-benchmark --quick
else
    ./target/release/sphincs-benchmark "$@"
fi
