//! Sink che scrive un riassunto leggibile di ogni evento su stdout.
//!
//! Pensato per l'uso interattivo (debug, demo, log durante lo sviluppo);
//! per l'ingestione automatizzata da parte di altri strumenti si
//! preferisce il sink `json` (Parte successiva di questo file).

use parking_lot::Mutex;
use std::io::{self, Write};

use crate::error::{AgentError, AgentResult};
use crate::events::NormalizedEvent;

use super::sink_trait::Sink;

/// Sink stdout. Il `Mutex` protegge la scrittura da interleaving quando
/// più stadi della pipeline scrivessero concorrentemente (attualmente non
/// il caso, dato un solo consumer, ma protegge da regressioni future).
pub struct StdoutSink {
    stdout: Mutex<io::Stdout>,
}

impl StdoutSink {
    pub fn new() -> Self {
        Self {
            stdout: Mutex::new(io::stdout()),
        }
    }
}

impl Default for StdoutSink {
    fn default() -> Self {
        Self::new()
    }
}

impl Sink for StdoutSink {
    fn name(&self) -> &'static str {
        "stdout"
    }

    fn write_event(&self, event: &NormalizedEvent) -> AgentResult<()> {
        let line = format_event_summary(event);
        let mut stdout = self.stdout.lock();
        writeln!(stdout, "{line}").map_err(AgentError::Io)
    }

    fn flush(&self) -> AgentResult<()> {
        self.stdout.lock().flush().map_err(AgentError::Io)
    }
}

/// Costruisce una riga di riassunto leggibile per un evento, includendo i
/// tag applicati dai detector e dal rules engine (i più rilevanti per un
/// operatore che legge il log in tempo reale).
pub fn format_event_summary(event: &NormalizedEvent) -> String {
    let tags = if event.tags.is_empty() {
        String::new()
    } else {
        format!(" [{}]", event.tags.join(", "))
    };

    format!(
        "{} {:?} pid={} comm={}{}",
        event.timestamp.format("%Y-%m-%dT%H:%M:%S%.3fZ"),
        event.event_kind,
        event.process.pid,
        event.process.comm,
        tags
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{EventKind, EventPayload, ProcessContext};
    use chrono::Utc;
    use uuid::Uuid;

    fn sample_event(tags: Vec<&str>) -> NormalizedEvent {
        NormalizedEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_kind: EventKind::Exec,
            process: ProcessContext {
                pid: 42,
                tgid: 42,
                ppid: 1,
                uid: 0,
                gid: 0,
                comm: "bash".to_string(),
                cgroup_id: 0,
                parent_comm: None,
            },
            payload: EventPayload::Exec {
                filename: "/bin/bash".to_string(),
                args: vec![],
            },
            container: None,
            tags: tags.into_iter().map(String::from).collect(),
        }
    }

    #[test]
    fn summary_includes_pid_and_comm() {
        let event = sample_event(vec![]);
        let summary = format_event_summary(&event);
        assert!(summary.contains("pid=42"));
        assert!(summary.contains("comm=bash"));
    }

    #[test]
    fn summary_includes_tags_when_present() {
        let event = sample_event(vec!["suspected_reverse_shell", "rule:builtin-reverse-shell"]);
        let summary = format_event_summary(&event);
        assert!(summary.contains("suspected_reverse_shell"));
        assert!(summary.contains("rule:builtin-reverse-shell"));
    }

    #[test]
    fn summary_omits_brackets_when_no_tags() {
        let event = sample_event(vec![]);
        let summary = format_event_summary(&event);
        assert!(!summary.contains('['));
    }

    #[test]
    fn stdout_sink_writes_without_error() {
        let sink = StdoutSink::new();
        let event = sample_event(vec![]);
        assert!(sink.write_event(&event).is_ok());
        assert!(sink.flush().is_ok());
    }
}