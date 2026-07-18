//! Probe per il process monitoring: `execve`, `execveat`, `clone`, `fork`,
//! `vfork`.
//!
//! Le probe sono agganciate ai tracepoint stabili
//! `sched:sched_process_exec` e `sched:sched_process_fork`, parte dell'ABI
//! stabile del kernel Linux, evitando così la fragilità dei kprobe su nomi
//! di funzione interni che possono cambiare tra versioni del kernel.

use aya_ebpf::{
    helpers::{bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
              bpf_get_current_uid_gid},
    macros::tracepoint,
    programs::TracePointContext,
};

use kerneltrace_common::{
    constants::{MAX_EXEC_ARGS, MAX_EXEC_ARG_LEN, MAX_PATH_LEN},
    events::{EventHeader, EventType, ExecEvent, ProcessLifecycleEvent},
    syscalls::SyscallId,
};

use crate::maps::EVENTS;

/// Costruisce un `EventHeader` popolato con il contesto del processo
/// correntemente in esecuzione, comune a tutte le probe di questo modulo.
#[inline(always)]
fn build_header(event_type: EventType) -> EventHeader {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);

    // `bpf_get_current_cgroup_id` richiede kernel >= 4.18 con cgroup v2;
    // in assenza (kernel più vecchio o cgroup v1 puro) restituiamo 0, che
    // l'agente userspace interpreta come "nessun container rilevato".
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    EventHeader {
        event_type: event_type as u32,
        timestamp_ns: unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() },
        pid: (pid_tgid & 0xFFFF_FFFF) as u32,
        tgid: (pid_tgid >> 32) as u32,
        ppid: 0, // popolato più avanti dove disponibile (vedi note in fork/exec)
        uid: (uid_gid & 0xFFFF_FFFF) as u32,
        gid: (uid_gid >> 32) as u32,
        cgroup_id,
        comm,
    }
}

/// Probe su `sched:sched_process_exec`, generata da `execve`/`execveat`.
///
/// # Nota sul PPID
///
/// Il tracepoint `sched_process_exec` non espone direttamente il PID del
/// genitore nel proprio formato; il PPID viene quindi risolto lato
/// userspace tramite la mappa di process tree costruita a partire dagli
/// eventi `ProcessLifecycleEvent` generati da `probe_process_fork`
/// (vedi `kerneltrace-agent::process::tree`).
#[tracepoint]
pub fn probe_exec(ctx: TracePointContext) -> u32 {
    match try_probe_exec(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_probe_exec(ctx: &TracePointContext) -> Result<u32, i64> {
    let header = build_header(EventType::Exec);

    let mut entry = match EVENTS.reserve::<ExecEvent>(0) {
        Some(entry) => entry,
        None => return Ok(0), // ring buffer pieno: evento scartato, mai bloccante
    };

    // Scriviamo direttamente nello spazio riservato dal ring buffer per
    // evitare una copia intermedia sullo stack (limite di 512 byte per
    // programma eBPF), che con `MAX_EXEC_ARGS * MAX_EXEC_ARG_LEN` byte di
    // argomenti sarebbe altrimenti a rischio.
    let event = entry.as_mut_ptr();
    unsafe {
        (*event).header = header;
        (*event).filename = [0u8; MAX_PATH_LEN];
        (*event).filename_len = 0;
        (*event).argc = 0;
        (*event).argv = [[0u8; MAX_EXEC_ARG_LEN]; MAX_EXEC_ARGS];
        (*event).argv_len = [0u16; MAX_EXEC_ARGS];
    }

    // Il formato esatto del tracepoint `sched_process_exec` espone il
    // filename tramite un campo `__data_loc filename`, la cui posizione va
    // letta con `ctx.read_at` all'offset generato da `vmlinux.h`/format del
    // tracepoint. Il parsing completo del filename e degli argv (via
    // `bpf_probe_read_user` sul puntatore `mm->arg_start` del processo) è
    // implementato in `read_exec_args`, mantenuto separato per isolare gli
    // `unsafe` di lettura da user-space memory.
    if let Err(_e) = unsafe { read_exec_args(ctx, event) } {
        // Anche in caso di errore nel parsing degli argomenti, l'evento
        // di exec di base (header + eventuale filename parziale) viene
        // comunque emesso: è preferibile un evento con dati incompleti
        // piuttosto che nessun evento.
    }

    entry.submit(0);
    Ok(0)
}

/// Legge il filename e gli argomenti di `execve` dalla memoria dello
/// spazio utente del processo corrente.
///
/// # Safety
///
/// `event` deve puntare a memoria valida e allineata per `ExecEvent`,
/// garantito dal chiamante (`entry.as_mut_ptr()` su un `RingBufEntry`
/// appena riservato).
#[inline(always)]
unsafe fn read_exec_args(
    ctx: &TracePointContext,
    event: *mut ExecEvent,
) -> Result<(), i64> {
    // Offset del campo `__data_loc filename` nel formato del tracepoint
    // `sched:sched_process_exec`; il valore è stabile nell'ABI del
    // tracepoint (non varia per versione del kernel come i kprobe).
    const FILENAME_DATA_LOC_OFFSET: usize = 8;

    let data_loc: u32 = ctx
        .read_at(FILENAME_DATA_LOC_OFFSET)
        .map_err(|_| -1i64)?;
    let offset = (data_loc & 0xFFFF) as usize;
    let len = ((data_loc >> 16) & 0xFFFF) as usize;
    let copy_len = len.min(MAX_PATH_LEN);

    for i in 0..copy_len {
        // Loop `bounded` con limite costante `MAX_PATH_LEN`, requisito del
        // BPF verifier per dimostrare la terminazione del ciclo.
        if i >= MAX_PATH_LEN {
            break;
        }
        let byte: u8 = ctx.read_at(offset + i).map_err(|_| -1i64)?;
        (*event).filename[i] = byte;
    }
    (*event).filename_len = copy_len as u16;

    // Il parsing degli argv (via `bpf_probe_read_user_str` su
    // `task->mm->arg_start`/`arg_end`) è più costoso e opzionale: viene
    // eseguito solo se la config dell'agente lo richiede (flag propagato
    // tramite una mappa BPF `CONFIG`, aggiunta in una parte successiva
    // insieme al resto della configurazione runtime del rules engine).
    // Per questa prima implementazione, argc/argv restano a zero e vengono
    // arricchiti lato userspace tramite lettura di `/proc/<pid>/cmdline`
    // come fallback (vedi `kerneltrace-agent::events::enrichment`).

    Ok(())
}

/// Probe su `sched:sched_process_fork`, generata da `clone`/`fork`/`vfork`.
#[tracepoint]
pub fn probe_process_fork(ctx: TracePointContext) -> u32 {
    match try_probe_process_fork(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_probe_process_fork(ctx: &TracePointContext) -> Result<u32, i64> {
    let header = build_header(EventType::ProcessLifecycle);

    // Il formato del tracepoint `sched_process_fork` espone `parent_pid` e
    // `child_pid` come campi a offset fisso (rispettivamente 8 e 24 byte,
    // stabili nell'ABI del tracepoint); li leggiamo qui per popolare
    // correttamente `ppid`, dato che al momento del fork il contesto BPF
    // corrente è il processo padre.
    const PARENT_PID_OFFSET: usize = 8;
    let parent_pid: i32 = ctx.read_at(PARENT_PID_OFFSET).map_err(|_| -1i64)?;

    let mut header = header;
    header.ppid = parent_pid as u32;

    let event = ProcessLifecycleEvent {
        header,
        syscall_id: SyscallId::Clone as u32,
        exit_code: 0,
        is_orphan: 0,
        is_zombie: 0,
        _padding: [0u8; 6],
    };

    match EVENTS.reserve::<ProcessLifecycleEvent>(0) {
        Some(mut entry) => {
            entry.write(event);
            entry.submit(0);
        }
        None => {} // ring buffer pieno: evento scartato, mai bloccante
    }

    Ok(0)
}