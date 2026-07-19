# Installazione

## Requisiti

- Linux kernel **≥ 5.8** (raccomandato ≥ 5.15 per supporto CO-RE completo
  e ring buffer BPF senza limitazioni)
- Rust **1.79+** stable (per l'agente/CLI) e **nightly** con componente
  `rust-src` (solo per compilare i programmi eBPF)
- `bpftool` e header del kernel, per generare `vmlinux.h`
- Privilegi `CAP_BPF` + `CAP_SYS_ADMIN` (o root) per caricare programmi eBPF

## Installazione da sorgente

```bash
git clone https://github.com/Gabryx412-coder/KernelTrace.git
cd kerneltrace

# Installa il toolchain nightly richiesto per il target BPF
rustup toolchain install nightly --component rust-src
rustup target add bpfel-unknown-none --toolchain nightly

# Genera vmlinux.h per il kernel corrente
./scripts/generate-vmlinux.sh

# Compila i programmi eBPF
cd crates/kerneltrace-ebpf
cargo +nightly build -Z build-std=core --release --target bpfel-unknown-none
cd ../..

# Compila l'agente e la CLI
cargo build --release -p kerneltrace-agent -p kerneltrace-cli
```

I binari risultanti si trovano in `target/release/kerneltrace-agent` e
`target/release/kerneltrace-cli`.

## Installazione tramite script

```bash
curl -fsSL https://raw.githubusercontent.com/kerneltrace/kerneltrace/main/scripts/install.sh | sudo bash
```

Lo script verifica i requisiti, compila (o scarica un binario release
precompilato per la propria architettura), installa i binari in
`/usr/local/bin`, copia il file di configurazione di esempio in
`/etc/kerneltrace/`, e installa l'unit systemd.

## Installazione del tool di management Python (opzionale)

```bash
cd management
pip install -e .
```

## Verifica dell'installazione

```bash
kerneltrace-cli status
kerneltrace-cli config print-default
```

Per l'avvio effettivo, vedi [quickstart.md](quickstart.md).