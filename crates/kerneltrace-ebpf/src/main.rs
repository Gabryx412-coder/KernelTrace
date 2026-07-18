//! Entry point del binario eBPF `kerneltrace-ebpf`.
//!
//! Questo crate viene compilato per il target `bpfel-unknown-none` (o
//! `bpfeb-unknown-none` su architetture big-endian) e produce un oggetto
//! ELF BPF che l'agente userspace (`kerneltrace-agent`) carica a runtime
//! tramite `aya::Ebpf::load`.
#![no_std]
#![no_main]

mod maps;
mod probes;

use aya_ebpf::panic_handler;

// Il panic handler per i target BPF non può fare nulla di utile (non esiste
// unwinding, non esiste output su stderr): si limita a un loop infinito
// dimostrabile dal verifier come "non terminante", pattern standard per i
// programmi eBPF in Rust.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// Re-esportiamo le probe definite in `probes::process` come simboli di
// primo livello del binario, così che `aya-ebpf` le registri come sezioni
// ELF distinte (`tracepoint/sched/sched_process_exec`, ecc.), caricabili
// indipendentemente dall'agente userspace.
pub use probes::process::{probe_exec, probe_process_fork};