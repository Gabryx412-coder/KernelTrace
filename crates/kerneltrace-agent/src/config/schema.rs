//! Schema della configurazione YAML di KernelTrace.
//!
//! Ogni struct qui deriva `Serialize`/`Deserialize` tramite `serde`, così
//! che la stessa struttura possa essere usata sia per il parsing del file
//! di configurazione sia per generarne uno di esempio (`--print-default-config`
//! nella CLI, Parte 13).

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Configurazione radice dell'agente KernelTrace.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Impostazioni generali dell'agente.
    #[serde(default)]
    pub agent: AgentSettings,

    /// Impostazioni di logging/tracing.
    #[serde(default)]
    pub logging: LoggingSettings,

    /// Quali categorie di monitoring sono attive.
    #[serde(default)]
    pub monitoring: MonitoringSettings,

    /// Configurazione del rules engine.
    #[serde(default)]
    pub rules: RulesSettings,

    /// Configurazione degli output sink.
    #[serde(default)]
    pub output: OutputSettings,

    /// Configurazione container awareness.
    #[serde(default)]
    pub container: ContainerSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSettings {
    /// Nome host riportato negli eventi (default: hostname di sistema).
    pub hostname: Option<String>,
    /// Dimensione del canale interno della pipeline eventi (backpressure).
    #[serde(default = "default_pipeline_capacity")]
    pub pipeline_capacity: usize,
    /// Percorso del file PID per il processo demonizzato.
    #[serde(default = "default_pid_file")]
    pub pid_file: PathBuf,
}

impl Default for AgentSettings {
    fn default() -> Self {
        Self {
            hostname: None,
            pipeline_capacity: default_pipeline_capacity(),
            pid_file: default_pid_file(),
        }
    }
}

fn default_pipeline_capacity() -> usize {
    8192
}

fn default_pid_file() -> PathBuf {
    PathBuf::from("/run/kerneltrace.pid")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "lowercase")]
pub enum LogFormat {
    Json,
    Pretty,
    Compact,
}

impl Default for LogFormat {
    fn default() -> Self {
        LogFormat::Json
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingSettings {
    /// Livello minimo di log (`trace`, `debug`, `info`, `warn`, `error`),
    /// compatibile con la sintassi `EnvFilter` di `tracing-subscriber`.
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default)]
    pub format: LogFormat,
    /// Directory dei log su file, se assente si logga solo su stdout.
    pub directory: Option<PathBuf>,
}

impl Default for LoggingSettings {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: LogFormat::default(),
            directory: None,
        }
    }
}

fn default_log_level() -> String {
    "info".to_string()
}

// In MonitoringSettings, aggiungiamo un campo per l'algoritmo di hash FIM:

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MonitoringSettings {
    #[serde(default = "default_true")]
    pub process: bool,
    #[serde(default = "default_true")]
    pub file_integrity: bool,
    #[serde(default = "default_true")]
    pub network: bool,
    #[serde(default = "default_true")]
    pub syscalls: bool,
    /// Path monitorati esplicitamente dal File Integrity Monitoring.
    #[serde(default)]
    pub fim_watch_paths: Vec<PathBuf>,
    /// Algoritmo di hashing usato dal FIM (`sha256` o `blake3`, default `blake3`).
    #[serde(default)]
    pub fim_hash_algorithm: crate::fim::HashAlgorithm,
}

impl Default for MonitoringSettings {
    fn default() -> Self {
        Self {
            process: true,
            file_integrity: true,
            network: true,
            syscalls: true,
            fim_watch_paths: Vec::new(),
            fim_hash_algorithm: crate::fim::HashAlgorithm::default(),
        }
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulesSettings {
    /// Directory contenenti le regole YAML built-in e community.
    #[serde(default = "default_rules_dirs")]
    pub directories: Vec<PathBuf>,
    /// Se true, un errore di parsing su una regola blocca l'avvio;
    /// se false, la regola viene ignorata con un warning.
    #[serde(default)]
    pub strict_parsing: bool,
}

impl Default for RulesSettings {
    fn default() -> Self {
        Self {
            directories: default_rules_dirs(),
            strict_parsing: false,
        }
    }
}

fn default_rules_dirs() -> Vec<PathBuf> {
    vec![PathBuf::from(
        "crates/kerneltrace-agent/src/detection/builtin_rules",
    )]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "lowercase")]
pub enum OutputSinkKind {
    Stdout,
    File,
    Json,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputSettings {
    #[serde(default = "default_sinks")]
    pub sinks: Vec<OutputSinkKind>,
    /// Path del file di output, usato quando `sinks` include `file`/`json`.
    pub file_path: Option<PathBuf>,
}

impl Default for OutputSettings {
    fn default() -> Self {
        Self {
            sinks: default_sinks(),
            file_path: None,
        }
    }
}

fn default_sinks() -> Vec<OutputSinkKind> {
    vec![OutputSinkKind::Stdout]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerSettings {
    #[serde(default = "default_true")]
    pub docker: bool,
    #[serde(default = "default_true")]
    pub podman: bool,
    #[serde(default = "default_true")]
    pub kubernetes: bool,
}

impl Default for ContainerSettings {
    fn default() -> Self {
        Self {
            docker: true,
            podman: true,
            kubernetes: true,
        }
    }
}