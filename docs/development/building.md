# Build del progetto

## Build a due stadi

KernelTrace richiede **due toolchain Rust distinte**:

1. **`nightly`** con componente `rust-src` e target `bpfel-unknown-none`,
   per compilare `crates/kerneltrace-ebpf` (richiede `-Z build-std=core`,
   una feature instabile necessaria per compilare `core` per un target
   BPF non ufficialmente supportato da rustup).
2. **`stable`** (versione fissata in `rust-toolchain.toml`), per
   compilare `kerneltrace-agent` e `kerneltrace-cli`.

```bash
# Stadio 1: programmi eBPF
rustup toolchain install nightly --component rust-src
rustup target add bpfel-unknown-none --toolchain nightly

cd crates/kerneltrace-ebpf
cargo +nightly build -Z build-std=core --release --target bpfel-unknown-none
cd ../..

# Stadio 2: agente e CLI (toolchain stable, vedi rust-toolchain.toml)
cargo build --release -p kerneltrace-agent -p kerneltrace-cli
```

## Generazione di `vmlinux.h`

Necessario per la tecnica CO-RE (Compile Once - Run Everywhere):

```bash
./scripts/generate-vmlinux.sh
```

Lo script usa `bpftool btf dump file /sys/kernel/btf/vmlinux format c` per
generare l'header con i layout delle struct del kernel corrente. Se
`bpftool` non è disponibile, installa il pacchetto `linux-tools-$(uname -r)`
sulla propria distribuzione.

## Build del tool Python

```bash
cd management
pip install -e ".[dev]"
```

## Setup ambiente di sviluppo completo

```bash
./scripts/setup-dev-env.sh
```

Lo script installa entrambi i toolchain Rust, i target necessari,
`bpftool`, e le dipendenze Python di sviluppo in un colpo solo.

## Note sulla cross-compilazione

Per target diversi da `x86_64-unknown-linux-gnu` (es.
`aarch64-unknown-linux-gnu`), è necessario un linker cross-compilante
(`gcc-aarch64-linux-gnu` su Debian/Ubuntu) — vedi il job
`build-release-binaries` in `.github/workflows/release.yml` per la
configurazione completa usata in CI.