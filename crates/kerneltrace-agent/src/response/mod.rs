//! Predisposizione architetturale per future azioni di risposta
//! automatica (kill processo, blocco IP, quarantena container, vedi
//! ROADMAP.md). Nessuna azione distruttiva reale è implementata in questa
//! fase; questo modulo espone l'interfaccia (`ResponseAction`) e un
//! dispatcher che applica il principio di sicurezza "dry-run by default".

pub mod action_trait;

pub use action_trait::{LoggingOnlyResponseAction, ResponseAction, ResponseDecision};

use tracing::warn;

use crate::events::NormalizedEvent;

/// Coordina l'esecuzione delle azioni di risposta configurate su ogni
/// evento. Isolato dal resto della pipeline (non implementa `Enricher`):
/// la risposta automatica è concettualmente un side-effect osservabile
/// all'esterno del sistema, distinto dall'arricchimento in-memory degli
/// eventi, e viene quindi invocato esplicitamente dal chiamante dopo che
/// la pipeline principale ha già arricchito e taggato l'evento.
pub struct ResponseDispatcher {
    actions: Vec<Box<dyn ResponseAction>>,
    /// Se `true` (default), nessuna azione distruttiva produce un effetto
    /// reale: viene solo loggato l'intento. Deve essere esplicitamente
    /// disabilitato in configurazione da un operatore consapevole prima
    /// che qualunque azione distruttiva venga eseguita realmente.
    dry_run: bool,
}

impl ResponseDispatcher {
    pub fn new(actions: Vec<Box<dyn ResponseAction>>, dry_run: bool) -> Self {
        if !dry_run {
            warn!("response dispatcher initialized with dry_run=false: destructive actions may execute for real");
        }
        Self { actions, dry_run }
    }

    /// Valuta tutte le azioni configurate contro un evento, eseguendo (o
    /// simulando, in base a `dry_run`) quelle applicabili.
    pub fn dispatch(&self, event: &NormalizedEvent) -> Vec<(&'static str, ResponseDecision)> {
        let mut results = Vec::new();

        for action in &self.actions {
            match action.execute(event, self.dry_run) {
                Ok(decision) => {
                    if decision != ResponseDecision::NotApplicable {
                        results.push((action.name(), decision));
                    }
                }
                Err(err) => {
                    warn!(action = action.name(), error = %err, "response action execution failed");
                }
            }
        }

        results
    }

    pub fn action_count(&self) -> usize {
        self.actions.len()
    }

    pub fn is_dry_run(&self) -> bool {
        self.dry_run
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{EventKind, EventPayload, ProcessContext};
    use chrono::Utc;
    use uuid::Uuid;

    fn event_with_tags(tags: Vec<&str>) -> NormalizedEvent {
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
    fn dispatch_runs_applicable_actions_only() {
        let dispatcher = ResponseDispatcher::new(
            vec![Box::new(LoggingOnlyResponseAction::new(
                "test-action",
                "suspected_reverse_shell",
            ))],
            true,
        );

        let event = event_with_tags(vec!["suspected_reverse_shell"]);
        let results = dispatcher.dispatch(&event);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "test-action");
        assert_eq!(results[0].1, ResponseDecision::WouldExecute);
    }

    #[test]
    fn dispatch_skips_inapplicable_actions() {
        let dispatcher = ResponseDispatcher::new(
            vec![Box::new(LoggingOnlyResponseAction::new(
                "test-action",
                "some_tag_not_present",
            ))],
            true,
        );

        let event = event_with_tags(vec!["unrelated_tag"]);
        let results = dispatcher.dispatch(&event);

        assert!(results.is_empty());
    }

    #[test]
    fn defaults_to_dry_run_semantics_when_constructed_with_true() {
        let dispatcher = ResponseDispatcher::new(vec![], true);
        assert!(dispatcher.is_dry_run());
    }

    #[test]
    fn action_count_reflects_configured_actions() {
        let dispatcher = ResponseDispatcher::new(
            vec![
                Box::new(LoggingOnlyResponseAction::new("a", "tag_a")),
                Box::new(LoggingOnlyResponseAction::new("b", "tag_b")),
            ],
            true,
        );
        assert_eq!(dispatcher.action_count(), 2);
    }
}