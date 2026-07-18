//! Tipi di evento normalizzato, usati da tutta la pipeline a valle del
//! parsing dei byte grezzi provenienti dal ring buffer.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Evento normalizzato, pronto per detection engine e output sink.
///
/// A differenza delle struct `#[repr(C)]` di `kerneltrace-common` (pensate
/// per l'efficienza di trasporto kernel -> userspace), questa struct è
/// pensata per leggibilità, serializzazione JSON e arricchimento
/// progressivo (container, process tree, hash file) nelle fasi successive
/// della pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedEvent {
    /// Identificatore univoco dell'evento, generato al momento della normalizzazione.
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub event_kind: EventKind,
    pub process: ProcessContext,
    /// Payload specifico del tipo di evento.
    pub payload: EventPayload,
    /// Popolato in una fase successiva della pipeline (`enrichment`), se il
    /// processo appartiene a un container riconosciuto.
    pub container: Option<ContainerContext>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessContext {
    pub pid: u32,
    pub tgid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub cgroup_id: u64,
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

/// Payload specifico per tipo di evento; le varianti aggiuntive
/// (file/network/ecc.) vengono popolate man mano che i moduli corrispondenti
/// vengono implementati nelle parti successive.
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
    /// Placeholder generico per tipi di evento non ancora implementati in
    /// questa parte dello sviluppo (file/network/ecc.).
    Raw {
        description: String,
    },
}