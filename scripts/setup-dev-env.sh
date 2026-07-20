#!/usr/bin/env bash
#
# Configura un ambiente di sviluppo completo per KernelTrace: entrambi i
# toolchain Rust (stable + nightly con target BPF), bpftool, e le
# dipendenze Python di sviluppo per il tool di management.

set -euo pipefail

echo "==> Verifica presenza di rustup..."
if ! command -v rustup &> /dev/null; then
    echo "rustup non trovato. Installalo da https://rustup.rs prima di continuare." >&2
    exit 1
fi

echo "==> Installazione toolchain stable (da rust-toolchain.toml)..."
rustup show

echo "==> Installazione toolchain nightly con rust-src per il target eBPF..."
rustup toolchain install nightly --component rust-src
rustup target add bpfel-unknown-none --toolchain nightly

echo "==> Installazione componenti aggiuntivi (rustfmt, clippy)..."
rustup component add rustfmt clippy

echo "==> Installazione tool cargo aggiuntivi (cargo-audit, cargo-deny, cargo-fuzz)..."
cargo install cargo-audit --locked || true
cargo install cargo-deny --locked || true
cargo install cargo-fuzz --locked || true

echo "==> Verifica presenza di bpftool..."
if ! command -v bpftool &> /dev/null; then
    echo "bpftool non trovato. Tentativo di installazione automatica..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get update
        sudo apt-get install -y "linux-tools-$(uname -r)" linux-tools-common || \
            echo "Installazione automatica fallita; installa bpftool manualmente." >&2
    else
        echo "Package manager non riconosciuto; installa bpftool manualmente per la tua distribuzione." >&2
    fi
fi

echo "==> Setup del tool di management Python..."
if command -v python3 &> /dev/null; then
    cd management
    python3 -m venv .venv
    # shellcheck disable=SC1091
    source .venv/bin/activate
    pip install -e ".[dev]"
    cd ..
    echo "Ambiente virtuale Python creato in management/.venv (attivalo con 'source management/.venv/bin/activate')"
else
    echo "python3 non trovato; il tool di management (opzionale) non è stato configurato." >&2
fi

echo ""
echo "==> Setup completato."
echo "Prossimi passi:"
echo "  1. ./scripts/generate-vmlinux.sh"
echo "  2. cd crates/kerneltrace-ebpf && cargo +nightly build -Z build-std=core --target bpfel-unknown-none"
echo "  3. cargo build --workspace --exclude kerneltrace-ebpf"
echo "  4. cargo test --workspace --exclude kerneltrace-ebpf"