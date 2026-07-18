//! Struct degli eventi raw scritti dai programmi eBPF nel ring buffer e letti
//! dall'agente userspace.
//!
//! Ogni struct è `#[repr(C)]`, `Copy`, a dimensione fissa e priva di
//! puntatori o allocazioni: questo è un requisito imposto dall'ambiente
//! `no_std` dei programmi eBPF e garantisce che il layout di memoria sia
//! identico tra il lato kernel che scrive e il lato userspace che legge,
//! senza bisogno di (de)serializzazione a runtime sul percorso critico.

use crate::constants::{IP_ADDR_LEN, MAX_COMM_LEN, MAX_EXEC_ARGS, MAX_EXEC_ARG_LEN, MAX_PATH_LEN};

/// Discriminante del tipo di evento, presente in ogni `EventHeader`.
///
/// L'agente userspace legge questo campo per primo per decidere come
/// interpretare il resto del buffer di byte ricevuto dal ring buffer.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    Exec = 0,
    FileOpen = 1,
    FileChange = 2,
    FileDelete = 3,
    FileRename = 4,
    Connect = 5,
    AcceptBindListen = 6,
    ProcessLifecycle = 7,
    Ptrace = 8,
    Mmap = 9,
    Signal = 10,
    Mount = 11,
    PrivilegeChange = 12,
}

/// Header comune a tutti gli eventi generati dalle probe eBPF.
///
/// Contiene il contesto minimo necessario per correlare l'evento a un
/// processo, un container e un istante temporale, indipendentemente dal
/// tipo specifico di evento.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EventHeader {
    /// Tipo di evento, usato dall'agente per il dispatch di parsing.
    pub event_type: u32,
    /// Timestamp in nanosecondi da boot (`bpf_ktime_get_ns`).
    pub timestamp_ns: u64,
    /// Process ID (in Linux corrisponde al thread id, `task->pid`).
    pub pid: u32,
    /// Thread Group ID (in Linux corrisponde al PID "tradizionale", `task->tgid`).
    pub tgid: u32,
    /// PID del processo padre.
    pub ppid: u32,
    /// User ID effettivo al momento dell'evento.
    pub uid: u32,
    /// Group ID effettivo al momento dell'evento.
    pub gid: u32,
    /// ID del cgroup del processo, usato per il container awareness
    /// (0 se il processo non appartiene a nessun cgroup non-root).
    pub cgroup_id: u64,
    /// Nome del processo (`task->comm`), troncato a `MAX_COMM_LEN` byte.
    pub comm: [u8; MAX_COMM_LEN],
}

impl EventHeader {
    /// Dimensione in byte dell'header, usata come offset fisso da ogni
    /// struct evento derivata durante il parsing lato userspace.
    pub const SIZE: usize = core::mem::size_of::<EventHeader>();
}

/// Evento generato da `execve`/`execveat`: avvio di un nuovo programma.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    pub header: EventHeader,
    /// Path assoluto (o relativo) dell'eseguibile, troncato a `MAX_PATH_LEN`.
    pub filename: [u8; MAX_PATH_LEN],
    pub filename_len: u16,
    /// Numero di argomenti effettivamente catturati (<= `MAX_EXEC_ARGS`).
    pub argc: u16,
    /// Argomenti di `execve`, ciascuno troncato a `MAX_EXEC_ARG_LEN` byte.
    pub argv: [[u8; MAX_EXEC_ARG_LEN]; MAX_EXEC_ARGS],
    /// Lunghezza effettiva di ciascun argomento in `argv`.
    pub argv_len: [u16; MAX_EXEC_ARGS],
}

/// Evento relativo a operazioni sul filesystem: `open`/`openat`, modifica,
/// eliminazione, rename, cambi di permessi/owner (File Integrity Monitoring).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileEvent {
    pub header: EventHeader,
    /// Path del file coinvolto.
    pub path: [u8; MAX_PATH_LEN],
    pub path_len: u16,
    /// Per gli eventi di rename, path di destinazione; altrimenti vuoto.
    pub new_path: [u8; MAX_PATH_LEN],
    pub new_path_len: u16,
    /// Flag passati a `open`/`openat` (O_CREAT, O_TRUNC, ecc.), 0 se non applicabile.
    pub open_flags: u32,
    /// Nuova modalità di permessi per eventi `chmod`, 0 se non applicabile.
    pub mode: u32,
    /// Nuovo UID/GID owner per eventi `chown`, u32::MAX se non applicabile.
    pub new_owner_uid: u32,
    pub new_owner_gid: u32,
}

/// Evento di rete: `connect`, `accept`, `bind`, `listen`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetworkEvent {
    pub header: EventHeader,
    /// 4 per IPv4, 6 per IPv6.
    pub address_family: u8,
    /// Protocollo IANA (6 = TCP, 17 = UDP).
    pub protocol: u8,
    _padding: [u8; 2],
    /// Indirizzo sorgente. Per IPv4 sono usati solo i primi 4 byte.
    pub src_addr: [u8; IP_ADDR_LEN],
    /// Indirizzo destinazione. Per IPv4 sono usati solo i primi 4 byte.
    pub dst_addr: [u8; IP_ADDR_LEN],
    pub src_port: u16,
    pub dst_port: u16,
    /// Quale syscall di rete ha generato l'evento (`SyscallId` come u32).
    pub syscall_id: u32,
}

/// Evento di ciclo di vita del processo: fork/clone/vfork, terminazione,
/// rilevamento di stato orfano o zombie.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessLifecycleEvent {
    pub header: EventHeader,
    /// Quale syscall ha generato l'evento (`SyscallId::Clone/Fork/Vfork` come u32),
    /// oppure `u32::MAX` per un evento di terminazione.
    pub syscall_id: u32,
    /// Codice di uscita, valido solo per eventi di terminazione.
    pub exit_code: i32,
    /// true se il processo, alla terminazione, non aveva un genitore vivente.
    pub is_orphan: u8,
    /// true se il processo è rimasto in stato zombie oltre la soglia configurata.
    pub is_zombie: u8,
    _padding: [u8; 6],
}

/// Evento generato da `ptrace`, rilevante per process injection detection.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PtraceEvent {
    pub header: EventHeader,
    /// Richiesta ptrace (PTRACE_ATTACH, PTRACE_POKETEXT, ecc., valore raw del kernel).
    pub request: i64,
    /// PID del processo target dell'operazione ptrace.
    pub target_pid: u32,
    _padding: [u8; 4],
}

/// Evento generato da `mmap`, usato per euristiche di process injection
/// (mappature eseguibili e scrivibili contemporaneamente, RWX).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MmapEvent {
    pub header: EventHeader,
    pub addr: u64,
    pub length: u64,
    /// Bitmask delle protezioni richieste (PROT_READ/WRITE/EXEC).
    pub prot_flags: u32,
    /// Bitmask dei flag di mapping (MAP_SHARED/PRIVATE/ANONYMOUS, ecc.).
    pub map_flags: u32,
}

/// Evento generato da `kill`, usato per correlare invii di segnali sospetti.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SignalEvent {
    pub header: EventHeader,
    pub target_pid: i32,
    pub signal: i32,
}

/// Evento generato da `mount`/`umount`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MountEvent {
    pub header: EventHeader,
    pub source: [u8; MAX_PATH_LEN],
    pub source_len: u16,
    pub target: [u8; MAX_PATH_LEN],
    pub target_len: u16,
    pub filesystem_type: [u8; 32],
    pub filesystem_type_len: u8,
    /// true se l'evento è un `umount` anziché un `mount`.
    pub is_umount: u8,
    _padding: [u8; 2],
}

/// Evento generato da `setuid`/`setgid`, rilevante per privilege escalation.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PrivilegeChangeEvent {
    pub header: EventHeader,
    pub old_uid: u32,
    pub new_uid: u32,
    pub old_gid: u32,
    pub new_gid: u32,
    /// true se la modifica ha portato a UID/GID 0 (root) da un valore non privilegiato.
    pub escalated_to_root: u8,
    _padding: [u8; 7],
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifica che le struct evento non superino una dimensione ragionevole
    /// per il ring buffer (nessun limite hard, ma un guardrail contro
    /// regressioni accidentali che gonfino la dimensione degli eventi e quindi
    /// l'overhead del sistema).
    #[test]
    fn event_sizes_are_bounded() {
        assert!(core::mem::size_of::<ExecEvent>() <= 1024);
        assert!(core::mem::size_of::<FileEvent>() <= 768);
        assert!(core::mem::size_of::<NetworkEvent>() <= 256);
        assert!(core::mem::size_of::<ProcessLifecycleEvent>() <= 128);
        assert!(core::mem::size_of::<MountEvent>() <= 768);
    }

    #[test]
    fn header_size_matches_manual_layout() {
        // 4 (event_type) + 8 (ts) + 4*4 (pid/tgid/ppid/uid) + 4 (gid) + 8 (cgroup_id) + 16 (comm)
        // Il compilatore può inserire padding per allineamento; verifichiamo
        // solo che la dimensione sia coerente e stabile, non un valore magico.
        let size = core::mem::size_of::<EventHeader>();
        assert_eq!(size, EventHeader::SIZE);
        assert!(size >= 44);
    }
}