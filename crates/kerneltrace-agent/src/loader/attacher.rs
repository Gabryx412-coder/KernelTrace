//! Caricamento e attach dei programmi eBPF tramite `aya`.

use aya::programs::TracePoint;
use aya::Ebpf;
use tracing::{info, warn};

use crate::error::{AgentError, AgentResult};

/// Byte compilati del binario eBPF, generato dal crate `kerneltrace-ebpf`
/// e incluso staticamente nel binario dell'agente.
static EBPF_PROGRAM_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/kerneltrace-ebpf.bpf.o"));

/// Carica l'oggetto eBPF in memoria e ne effettua il parsing tramite `aya`.
pub fn load_ebpf_object() -> AgentResult<Ebpf> {
    let ebpf = Ebpf::load(EBPF_PROGRAM_BYTES)?;
    info!("eBPF object loaded successfully");
    Ok(ebpf)
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

/// Attacca le probe di process monitoring (`execve`/`clone`/`fork`/`vfork`).
pub fn attach_process_probes(ebpf: &mut Ebpf) -> AgentResult<()> {
    attach_tracepoint(ebpf, "probe_exec", "sched", "sched_process_exec")?;
    attach_tracepoint(ebpf, "probe_process_fork", "sched", "sched_process_fork")?;
    Ok(())
}

/// Attacca le probe di file monitoring (`open`/`unlink`/`rename`/`chmod`/`chown`).
pub fn attach_file_probes(ebpf: &mut Ebpf) -> AgentResult<()> {
    attach_tracepoint(ebpf, "probe_openat", "syscalls", "sys_enter_openat")?;
    attach_tracepoint(ebpf, "probe_unlink", "syscalls", "sys_enter_unlinkat")?;
    attach_tracepoint(ebpf, "probe_rename", "syscalls", "sys_enter_renameat2")?;
    attach_tracepoint(ebpf, "probe_chmod", "syscalls", "sys_enter_fchmodat")?;
    attach_tracepoint(ebpf, "probe_chown", "syscalls", "sys_enter_fchownat")?;
    Ok(())
}

/// Attacca le probe di network monitoring (`connect`/`bind`/`listen`/`accept`).
pub fn attach_network_probes(ebpf: &mut Ebpf) -> AgentResult<()> {
    attach_tracepoint(ebpf, "probe_connect", "syscalls", "sys_enter_connect")?;
    attach_tracepoint(ebpf, "probe_bind", "syscalls", "sys_enter_bind")?;
    attach_tracepoint(ebpf, "probe_listen", "syscalls", "sys_enter_listen")?;
    attach_tracepoint(ebpf, "probe_accept", "syscalls", "sys_exit_accept4")?;
    Ok(())
}

/// Attacca le probe di privilege monitoring (`ptrace`/`setuid`/`setgid`).
pub fn attach_privilege_probes(ebpf: &mut Ebpf) -> AgentResult<()> {
    attach_tracepoint(ebpf, "probe_ptrace", "syscalls", "sys_enter_ptrace")?;
    attach_tracepoint(ebpf, "probe_setuid", "syscalls", "sys_enter_setuid")?;
    attach_tracepoint(ebpf, "probe_setgid", "syscalls", "sys_enter_setgid")?;
    Ok(())
}

/// Attacca la probe di memory monitoring (`mmap`).
pub fn attach_memory_probes(ebpf: &mut Ebpf) -> AgentResult<()> {
    attach_tracepoint(ebpf, "probe_mmap", "syscalls", "sys_enter_mmap")?;
    Ok(())
}

/// Attacca la probe di signal monitoring (`kill`).
pub fn attach_signal_probes(ebpf: &mut Ebpf) -> AgentResult<()> {
    attach_tracepoint(ebpf, "probe_kill", "syscalls", "sys_enter_kill")?;
    Ok(())
}

/// Attacca le probe di mount monitoring (`mount`/`umount`).
pub fn attach_mount_probes(ebpf: &mut Ebpf) -> AgentResult<()> {
    attach_tracepoint(ebpf, "probe_mount", "syscalls", "sys_enter_mount")?;
    attach_tracepoint(ebpf, "probe_umount", "syscalls", "sys_enter_umount")?;
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