//! Caricamento e attach dei programmi eBPF tramite `aya`.

use aya::programs::TracePoint;
use aya::Ebpf;
use tracing::{info, warn};

use crate::error::{AgentError, AgentResult};

/// Byte compilati del binario eBPF, generato dal crate `kerneltrace-ebpf`
/// e incluso staticamente nel binario dell'agente.
///
/// Il percorso è relativo alla directory di output della build eBPF
/// (gestita dal Makefile radice, target `build-ebpf`), non al crate
/// `kerneltrace-agent` stesso.
static EBPF_PROGRAM_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/kerneltrace-ebpf.bpf.o"));

/// Carica l'oggetto eBPF in memoria e ne effettua il parsing tramite `aya`.
///
/// Richiede privilegi `CAP_BPF`/`CAP_SYS_ADMIN` (o root): un fallimento qui
/// è quasi sempre dovuto a permessi insufficienti, quindi il messaggio di
/// errore viene arricchito di conseguenza in `main.rs`.
pub fn load_ebpf_object() -> AgentResult<Ebpf> {
    let ebpf = Ebpf::load(EBPF_PROGRAM_BYTES)?;
    info!("eBPF object loaded successfully");
    Ok(ebpf)
}

/// Attacca tutte le probe di process monitoring (`probe_exec`,
/// `probe_process_fork`) ai rispettivi tracepoint del kernel.
///
/// Le probe aggiuntive (file/network/privilege/memory/signal/mount) vengono
/// attaccate da funzioni analoghe aggiunte in una parte successiva, una
/// volta implementate le rispettive sezioni ELF nel crate `kerneltrace-ebpf`.
pub fn attach_process_probes(ebpf: &mut Ebpf) -> AgentResult<()> {
    attach_tracepoint(ebpf, "probe_exec", "sched", "sched_process_exec")?;
    attach_tracepoint(ebpf, "probe_process_fork", "sched", "sched_process_fork")?;
    Ok(())
}

fn attach_tracepoint(
    ebpf: &mut Ebpf,
    program_name: &'static str,
    category: &str,
    name: &str,
) -> AgentResult<()> {
    let program: &mut TracePoint = ebpf
        .program_mut(program_name)
        .ok_or(AgentError::RingBufMapNotFound(program_name))?
        .try_into()
        .map_err(|source| AgentError::EbpfAttach {
            program: program_name,
            source,
        })?;

    program.load().map_err(|source| AgentError::EbpfAttach {
        program: program_name,
        source,
    })?;

    program
        .attach(category, name)
        .map_err(|source| AgentError::EbpfAttach {
            program: program_name,
            source,
        })?;

    info!(program = program_name, category, name, "eBPF probe attached");
    Ok(())
}

/// Verifica preliminare dei privilegi correnti, per fornire un messaggio di
/// errore chiaro prima ancora di tentare il caricamento eBPF.
pub fn check_privileges() -> AgentResult<()> {
    let uid = nix::unistd::Uid::current();
    if !uid.is_root() {
        warn!("KernelTrace is not running as root; eBPF loading may fail without CAP_BPF/CAP_SYS_ADMIN");
    }
    Ok(())
}