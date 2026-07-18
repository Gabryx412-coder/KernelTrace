//! Tipo di errore centrale dell'agente userspace.
//!
//! Usiamo `thiserror` per gli errori delle interfacce pubbliche dei moduli
//! (con varianti tipizzate, utili per il matching a monte) e `anyhow` nei
//! punti di ingresso (`main.rs`) dove basta propagare un contesto leggibile.

use std::path::PathBuf;
use thiserror::Error;

/// Errore generale dell'agente KernelTrace.
#[derive(Debug, Error)]
pub enum AgentError {
    #[error("failed to load configuration from {path}: {source}")]
    ConfigLoad {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },

    #[error("configuration validation failed: {0}")]
    ConfigValidation(String),

    #[error("failed to load eBPF program: {0}")]
    EbpfLoad(#[from] aya::EbpfError),

    #[error("failed to attach eBPF program '{program}': {source}")]
    EbpfAttach {
        program: &'static str,
        #[source]
        source: aya::programs::ProgramError,
    },

    #[error("ring buffer map '{0}' not found in eBPF object")]
    RingBufMapNotFound(&'static str),

    #[error("event pipeline channel closed unexpectedly")]
    PipelineClosed,

    #[error("failed to parse event buffer: {0}")]
    EventParse(#[from] kerneltrace_common::CommonError),

    #[error("rule parsing error in {path}: {message}")]
    RuleParse { path: PathBuf, message: String },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("insufficient privileges: {0}. KernelTrace requires CAP_BPF and CAP_SYS_ADMIN (or root) to load eBPF programs.")]
    InsufficientPrivileges(String),
}

/// Alias di convenienza per i `Result` interni dell'agente.
pub type AgentResult<T> = Result<T, AgentError>;