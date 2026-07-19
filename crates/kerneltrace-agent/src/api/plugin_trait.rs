//! Trait di estensibilità generica per plugin di terze parti.
//!
//! Predisposizione architetturale per l'ecosistema futuro di KernelTrace:
//! un plugin può osservare eventi normalizzati (in sola lettura, senza
//! poterli modificare direttamente, a differenza di un `Enricher` interno)
//! per implementare integrazioni custom — es. l'invio di eventi verso un
//! sistema proprietario, senza dover forkare il progetto o attendere che
//! un sink venga aggiunto al core.
//!
//! Non esiste ancora un meccanismo di caricamento dinamico (es. tramite
//! `libloading` o WASM); i plugin, in questa fase, sono implementazioni
//! Rust statiche del trait, compilate insieme all'agente. Il meccanismo di
//! caricamento dinamico è tracciato come miglioramento futuro in
//! ROADMAP.md, e la scelta di un trait a metodi sincroni e senza stato
//! condiviso obbligatorio rende quella migrazione incrementale piuttosto
//! che un redesign.

use crate::events::NormalizedEvent;

/// Metadati identificativi di un plugin, usati nei log diagnostici e in
/// una futura interfaccia di gestione (`kerneltrace-cli plugins list`).
#[derive(Debug, Clone)]
pub struct PluginMetadata {
    pub name: &'static str,
    pub version: &'static str,
    pub description: &'static str,
}

/// Interfaccia comune per un plugin che osserva il flusso di eventi in
/// sola lettura, a valle di tutti gli stadi di arricchimento e detection.
pub trait Plugin: Send + Sync {
    /// Metadati del plugin.
    fn metadata(&self) -> PluginMetadata;

    /// Invocato per ogni evento che raggiunge lo stadio finale della
    /// pipeline (dopo rules engine e, quando disponibile, anomaly
    /// detection). Gli errori restituiti vengono loggati dal chiamante
    /// senza interrompere il flusso degli eventi verso gli altri plugin o
    /// verso gli output sink.
    fn on_event(&self, event: &NormalizedEvent) -> Result<(), String>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{EventKind, EventPayload, ProcessContext};
    use chrono::Utc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use uuid::Uuid;

    struct CountingPlugin {
        count: Arc<AtomicUsize>,
    }

    impl Plugin for CountingPlugin {
        fn metadata(&self) -> PluginMetadata {
            PluginMetadata {
                name: "counting-plugin",
                version: "0.1.0",
                description: "test plugin",
            }
        }

        fn on_event(&self, _event: &NormalizedEvent) -> Result<(), String> {
            self.count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn plugin_receives_events() {
        let count = Arc::new(AtomicUsize::new(0));
        let plugin = CountingPlugin {
            count: Arc::clone(&count),
        };

        let event = NormalizedEvent {
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
        };

        plugin.on_event(&event).unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn metadata_exposes_expected_fields() {
        let plugin = CountingPlugin {
            count: Arc::new(AtomicUsize::new(0)),
        };
        let metadata = plugin.metadata();
        assert_eq!(metadata.name, "counting-plugin");
        assert_eq!(metadata.version, "0.1.0");
    }
}