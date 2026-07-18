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

// Il panic handler per i target BPF non può fare nulla di utile (non esiste
// unwinding, non esiste output su stderr): si limita a un loop infinito
// dimostrabile dal verifier come "non terminante", pattern standard per i
// programmi eBPF in Rust.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// Re-esportiamo tutte le probe come simboli di primo livello del binario,
// così che `aya-ebpf` le registri come sezioni ELF distinte, caricabili e
// attaccabili indipendentemente dall'agente userspace in base alla
// configurazione (`monitoring.*` in kerneltrace.yaml).
pub use probes::file::{probe_chmod, probe_chown, probe_openat, probe_rename, probe_unlink};
pub use probes::memory::probe_mmap;
pub use probes::mount::{probe_mount, probe_umount};
pub use probes::network::{probe_accept, probe_bind, probe_connect, probe_listen};
pub use probes::privilege::{probe_ptrace, probe_setgid, probe_setuid};
pub use probes::process::{probe_exec, probe_process_fork};
pub use probes::signal::probe_kill;