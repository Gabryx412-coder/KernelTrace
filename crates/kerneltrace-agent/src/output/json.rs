//! Sink che scrive ogni evento come una riga JSON (formato JSON Lines,
//! `.jsonl`) su un file, il formato standard per l'ingestione da parte di
//! strumenti di log shipping (Filebeat, Fluentd, Vector) verso SIEM
//! esterni (Elastic, Splunk) — l'aggancio naturale per le integrazioni
//! pianificate in `ROADMAP.md` senza dover implementare da subito un
//! client di rete dedicato per ciascun sistema esterno.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use parking_lot::Mutex;

use crate::error::{AgentError, AgentResult};
use crate::events::NormalizedEvent;

use super::sink_trait::Sink;

/// Sink JSON Lines: ogni evento è serializzato come un oggetto JSON su
/// una singola riga, appeso al file configurato.
pub struct JsonSink {
    path: PathBuf,
    writer: Mutex<BufWriter<File>>,
}

impl JsonSink {
    /// Apre (creando se necessario) il file di output in modalità append,
    /// così che i riavvii dell'agente non sovrascrivano gli eventi già
    /// registrati.
    pub fn new(path: impl AsRef<Path>) -> AgentResult<Self> {
        let path = path.as_ref().to_path_buf();

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(AgentError::Io)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(AgentError::Io)?;

        Ok(Self {
            path,
            writer: Mutex::new(BufWriter::new(file)),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Sink for JsonSink {
    fn name(&self) -> &'static str {
        "json"
    }

    fn write_event(&self, event: &NormalizedEvent) -> AgentResult<()> {
        let json = serde_json::to_string(event)
            .map_err(|err| AgentError::ConfigValidation(format!("JSON serialization failed: {err}")))?;

        let mut writer = self.writer.lock();
        writeln!(writer, "{json}").map_err(AgentError::Io)
    }

    fn flush(&self) -> AgentResult<()> {
        self.writer.lock().flush().map_err(AgentError::Io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{EventKind, EventPayload, ProcessContext};
    use chrono::Utc;
    use uuid::Uuid;

    fn sample_event() -> NormalizedEvent {
        NormalizedEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_kind: EventKind::Exec,
            process: ProcessContext {
                pid: 1,
                tgid: 1,
                ppid: 0,
                uid: 0,
                gid: 0,
                comm: "init".to_string(),
                cgroup_id: 0,
                parent_comm: None,
            },
            payload: EventPayload::Exec {
                filename: "/sbin/init".to_string(),
                args: vec![],
            },
            container: None,
            tags: vec![],
        }
    }

    #[test]
    fn writes_valid_json_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");

        let sink = JsonSink::new(&path).unwrap();
        sink.write_event(&sample_event()).unwrap();
        sink.flush().unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        let line = contents.lines().next().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(parsed["process"]["comm"], "init");
    }

    #[test]
    fn appends_across_multiple_writes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");

        let sink = JsonSink::new(&path).unwrap();
        sink.write_event(&sample_event()).unwrap();
        sink.write_event(&sample_event()).unwrap();
        sink.flush().unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents.lines().count(), 2);
    }

    #[test]
    fn reopening_path_appends_instead_of_truncating() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");

        {
            let sink = JsonSink::new(&path).unwrap();
            sink.write_event(&sample_event()).unwrap();
            sink.flush().unwrap();
        }
        {
            let sink = JsonSink::new(&path).unwrap();
            sink.write_event(&sample_event()).unwrap();
            sink.flush().unwrap();
        }

        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents.lines().count(), 2);
    }

    #[test]
    fn creates_parent_directories_if_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("dir").join("events.jsonl");

        let sink = JsonSink::new(&path).unwrap();
        sink.write_event(&sample_event()).unwrap();

        assert!(path.exists());
    }
}