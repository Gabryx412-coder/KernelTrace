//! Tipi di evento normalizzato, usati da tutta la pipeline a valle del
//! parsing dei byte grezzi provenienti dal ring buffer.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Evento normalizzato, pronto per detection engine e output sink.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub event_kind: EventKind,
    pub process: ProcessContext,
    pub payload: EventPayload,
    pub container: Option<ContainerContext>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Exec,
    FileOpen,
    FileChange,
    FileDelete,
    FileRename,
    Connect,
    AcceptBindListen,
    ProcessLifecycle,
    Ptrace,
    Mmap,
    Signal,
    Mount,
    PrivilegeChange,
}

// In ProcessContext, aggiungiamo il nome del processo padre (risolto dal
// ProcessTree quando disponibile), necessario per regole come "bash
// spawnata da nginx".

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessContext {
    pub pid: u32,
    pub tgid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub cgroup_id: u64,
    /// Nome del processo padre, risolto da `ProcessTreeEnricher` quando il
    /// PPID è presente nel process tree tracciato. `None` se il padre non
    /// è (ancora) stato osservato.
    #[serde(default)]
    pub parent_comm: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerContext {
    pub runtime: ContainerRuntime,
    pub container_id: String,
    pub pod_name: Option<String>,
    pub namespace: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ContainerRuntime {
    Docker,
    Podman,
    Kubernetes,
}

/// Payload specifico per tipo di evento.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventPayload {
    Exec {
        filename: String,
        args: Vec<String>,
    },
    ProcessLifecycle {
        syscall: String,
        exit_code: Option<i32>,
        is_orphan: bool,
        is_zombie: bool,
    },
    File {
        path: String,
        new_path: Option<String>,
        open_flags: u32,
        mode: Option<u32>,
        new_owner_uid: Option<u32>,
        new_owner_gid: Option<u32>,
    },
    Network {
        address_family: u8,
        protocol: u8,
        src_addr: String,
        dst_addr: String,
        src_port: u16,
        dst_port: u16,
        syscall: String,
    },
    Ptrace {
        request: i64,
        target_pid: u32,
    },
    Mmap {
        addr: u64,
        length: u64,
        prot_flags: u32,
        map_flags: u32,
    },
    Signal {
        target_pid: i32,
        signal: i32,
    },
    Mount {
        source: Option<String>,
        target: String,
        filesystem_type: Option<String>,
        is_umount: bool,
    },
    PrivilegeChange {
        old_uid: u32,
        new_uid: u32,
        old_gid: u32,
        new_gid: u32,
        escalated_to_root: bool,
    },
    /// Placeholder generico per eventuali tipi di evento futuri non ancora
    /// modellati esplicitamente.
    Raw {
        description: String,
    },
}