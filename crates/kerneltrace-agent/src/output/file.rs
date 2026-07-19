//! Sink che scrive un riassunto testuale (stesso formato di `StdoutSink`)
//! su un file, utile per un log human-readable persistente separato
//! dall'output strutturato JSON, es. per revisione manuale rapida senza
//! dover parsare JSON.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use parking_lot::Mutex;

use crate::error::{AgentError, AgentResult};
use crate::events::NormalizedEvent;

use super::stdout::format_event_summary;
use super::sink_trait::Sink;

/// Sink su file in formato testuale leggibile (non JSON).
pub struct FileSink {
    path: PathBuf,
    writer: Mutex<BufWriter<File>>,
}

impl FileSink {
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

impl Sink for FileSink {
    fn name(&self) -> &'static str {
        "file"
    }

    fn write_event(&self, event: &NormalizedEvent) -> AgentResult<()> {
        let line = format_event_summary(event);
        let mut writer = self.writer.lock();
        writeln!(writer, "{line}").map_err(AgentError::Io)
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
                pid: 7,
                tgid: 7,
                ppid: 1,
                uid: 0,
                gid: 0,
                comm: "cron".to_string(),
                cgroup_id: 0,
                parent_comm: None,
            },
            payload: EventPayload::Exec {
                filename: "/usr/sbin/cron".to_string(),
                args: vec![],
            },
            container: None,
            tags: vec![],
        }
    }

    #[test]
    fn writes_human_readable_line_to_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.log");

        let sink = FileSink::new(&path).unwrap();
        sink.write_event(&sample_event()).unwrap();
        sink.flush().unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("comm=cron"));
    }

    #[test]
    fn appends_rather_than_truncates_on_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.log");

        {
            let sink = FileSink::new(&path).unwrap();
            sink.write_event(&sample_event()).unwrap();
            sink.flush().unwrap();
        }
        {
            let sink = FileSink::new(&path).unwrap();
            sink.write_event(&sample_event()).unwrap();
            sink.flush().unwrap();
        }

        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents.lines().count(), 2);
    }
}