//! Output sink: destinazioni configurabili verso cui la pipeline invia
//! gli eventi normalizzati dopo l'arricchimento e la valutazione delle
//! regole. Ogni sink implementa il trait [`Sink`], permettendo di
//! aggiungere in futuro destinazioni verso sistemi esterni (Elastic,
//! Splunk, Kafka, webhook) senza modificare il resto della pipeline.

pub mod file;
pub mod json;
pub mod sink_trait;
pub mod stdout;

pub use file::FileSink;
pub use json::JsonSink;
pub use sink_trait::Sink;
pub use stdout::StdoutSink;

use tracing::warn;

use crate::events::NormalizedEvent;

/// Gestore degli output sink configurati: inoltra ogni evento a tutti i
/// sink attivi, isolando i fallimenti di un singolo sink dagli altri.
pub struct OutputManager {
    sinks: Vec<Box<dyn Sink>>,
}

impl OutputManager {
    pub fn new(sinks: Vec<Box<dyn Sink>>) -> Self {
        Self { sinks }
    }

    /// Inoltra un evento a tutti i sink configurati. Un errore su un sink
    /// viene loggato ma non impedisce la scrittura sugli altri: un sink
    /// che fallisce (es. disco pieno per il sink `file`) non deve
    /// silenziare completamente l'osservabilità dell'agente se altri sink
    /// (es. `stdout`) funzionano ancora.
    pub fn dispatch(&self, event: &NormalizedEvent) {
        for sink in &self.sinks {
            if let Err(err) = sink.write_event(event) {
                warn!(sink = sink.name(), error = %err, "failed to write event to sink");
            }
        }
    }

    /// Esegue il flush di tutti i sink, tipicamente chiamato allo
    /// shutdown dell'agente per garantire che i buffer interni (es.
    /// `BufWriter` dei sink su file) vengano svuotati su disco.
    pub fn flush_all(&self) {
        for sink in &self.sinks {
            if let Err(err) = sink.flush() {
                warn!(sink = sink.name(), error = %err, "failed to flush sink");
            }
        }
    }

    pub fn sink_count(&self) -> usize {
        self.sinks.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{EventKind, EventPayload, ProcessContext};
    use chrono::Utc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use uuid::Uuid;

    /// Sink di test che conta le invocazioni, per verificare che
    /// `OutputManager` inoltri effettivamente a tutti i sink configurati.
    struct CountingSink {
        count: Arc<AtomicUsize>,
        fail: bool,
    }

    impl Sink for CountingSink {
        fn name(&self) -> &'static str {
            "counting"
        }

        fn write_event(&self, _event: &NormalizedEvent) -> crate::error::AgentResult<()> {
            self.count.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                Err(crate::error::AgentError::ConfigValidation("simulated failure".to_string()))
            } else {
                Ok(())
            }
        }
    }

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
                comm: "test".to_string(),
                cgroup_id: 0,
                parent_comm: None,
            },
            payload: EventPayload::Exec {
                filename: "/bin/test".to_string(),
                args: vec![],
            },
            container: None,
            tags: vec![],
        }
    }

    #[test]
    fn dispatch_forwards_to_all_sinks() {
        let count_a = Arc::new(AtomicUsize::new(0));
        let count_b = Arc::new(AtomicUsize::new(0));

        let manager = OutputManager::new(vec![
            Box::new(CountingSink {
                count: Arc::clone(&count_a),
                fail: false,
            }),
            Box::new(CountingSink {
                count: Arc::clone(&count_b),
                fail: false,
            }),
        ]);

        manager.dispatch(&sample_event());

        assert_eq!(count_a.load(Ordering::SeqCst), 1);
        assert_eq!(count_b.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn failing_sink_does_not_prevent_other_sinks_from_receiving_event() {
        let count_failing = Arc::new(AtomicUsize::new(0));
        let count_ok = Arc::new(AtomicUsize::new(0));

        let manager = OutputManager::new(vec![
            Box::new(CountingSink {
                count: Arc::clone(&count_failing),
                fail: true,
            }),
            Box::new(CountingSink {
                count: Arc::clone(&count_ok),
                fail: false,
            }),
        ]);

        manager.dispatch(&sample_event());

        assert_eq!(count_failing.load(Ordering::SeqCst), 1);
        assert_eq!(count_ok.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn sink_count_reflects_configured_sinks() {
        let manager = OutputManager::new(vec![
            Box::new(CountingSink {
                count: Arc::new(AtomicUsize::new(0)),
                fail: false,
            }),
            Box::new(CountingSink {
                count: Arc::new(AtomicUsize::new(0)),
                fail: false,
            }),
        ]);
        assert_eq!(manager.sink_count(), 2);
    }
}