# Panoramica architetturale

KernelTrace è organizzato in quattro macro-livelli, ciascuno con
responsabilità nettamente separate e comunicanti attraverso interfacce
esplicite (trait Rust o canali `tokio`), non attraverso stato globale
condiviso implicitamente.

## Livelli dell'architettura
┌─────────────────────────────────────────────────────────────┐
│  Kernel space                                                │
│  crates/kerneltrace-ebpf — probe eBPF (CO-RE), no_std        │
└───────────────────────────┬───────────────────────────────────┘
     │ Ring buffer BPF (zero-copy)
┌───────────────────────────▼───────────────────────────────────┐
│  Userspace agent — crates/kerneltrace-agent                   │
│                                                                 │
│  loader → events (pipeline) → [enrichers] → detection → output │
└───────────────────────────┬───────────────────────────────────┘
│
┌───────────────────────────▼───────────────────────────────────┐
│  Management                                                    │
│  crates/kerneltrace-cli (Rust, privilegiato)                   │
│  management/ (Python, non privilegiato)                        │
└─────────────────────────────────────────────────────────────────┘
