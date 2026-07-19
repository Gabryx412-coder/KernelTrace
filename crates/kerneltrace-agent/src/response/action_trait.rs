//! Trait per future azioni di risposta automatica (kill del processo,
//! blocco IP, quarantena container), predisposte architetturalmente ma
//! non implementate in questa fase del progetto (vedi ROADMAP.md).
//!
//! # Filosofia di design: sicurezza prima di tutto
//!
//! Le azioni di risposta automatica hanno un potenziale distruttivo (kill
//! di un processo di produzione, blocco di un IP legittimo per un falso
//! positivo). Per questo il trait è progettato attorno a un principio di
//! **dry-run by default**: ogni implementazione futura deve dichiarare
//! esplicitamente se un'azione è distruttiva (`is_destructive`), e il
//! chiamante (non ancora implementato in questa fase, si veda
//! `DryRunResponseAction` sotto) può decidere di eseguire solo azioni non
//! distruttive finché un operatore non abilita esplicitamente la modalità
//! attiva in configurazione.

use crate::error::AgentResult;
use crate::events::NormalizedEvent;

/// Esito dell'applicabilità di un'azione di risposta a un dato evento.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseDecision {
    /// L'azione non si applica a questo evento (nessuna condizione soddisfatta).
    NotApplicable,
    /// L'azione si applicherebbe, ma è stata solo simulata (dry-run).
    WouldExecute,
    /// L'azione è stata eseguita realmente.
    Executed,
}

/// Interfaccia comune per un'azione di risposta automatica.
pub trait ResponseAction: Send + Sync {
    /// Nome dell'azione, usato nei log e nella configurazione
    /// (`response.actions`, campo pianificato per una fase futura).
    fn name(&self) -> &'static str;

    /// Indica se l'azione ha effetti distruttivi o irreversibili (kill,
    /// blocco di rete) rispetto ad azioni puramente informative. Usato dal
    /// chiamante per decidere se richiedere una conferma esplicita
    /// nell'implementazione futura del dispatcher di risposta.
    fn is_destructive(&self) -> bool;

    /// Determina se l'azione si applica all'evento dato (es. l'evento è
    /// taggato `rule:builtin-reverse-shell-interactive` con severità
    /// `critical`).
    fn applies_to(&self, event: &NormalizedEvent) -> bool;

    /// Esegue l'azione. Le implementazioni concrete devono rispettare la
    /// working assumption di `dry_run`: se `true`, l'implementazione deve
    /// limitarsi a loggare l'intento senza produrre alcun effetto reale
    /// sul sistema.
    fn execute(&self, event: &NormalizedEvent, dry_run: bool) -> AgentResult<ResponseDecision>;
}

/// Implementazione segnaposto che logga l'intento di risposta senza
/// eseguire alcuna azione reale, utilizzabile come azione di default o
/// come base per costruire azioni concrete future (kill/blocco
/// IP/quarantena) mantenendo la stessa interfaccia di logging.
pub struct LoggingOnlyResponseAction {
    name: &'static str,
    trigger_tag: String,
}

impl LoggingOnlyResponseAction {
    pub fn new(name: &'static str, trigger_tag: impl Into<String>) -> Self {
        Self {
            name,
            trigger_tag: trigger_tag.into(),
        }
    }
}

impl ResponseAction for LoggingOnlyResponseAction {
    fn name(&self) -> &'static str {
        self.name
    }

    fn is_destructive(&self) -> bool {
        false
    }

    fn applies_to(&self, event: &NormalizedEvent) -> bool {
        event.tags.iter().any(|t| t == &self.trigger_tag)
    }

    fn execute(&self, event: &NormalizedEvent, _dry_run: bool) -> AgentResult<ResponseDecision> {
        if !self.applies_to(event) {
            return Ok(ResponseDecision::NotApplicable);
        }

        tracing::info!(
            action = self.name,
            pid = event.process.pid,
            comm = %event.process.comm,
            trigger_tag = %self.trigger_tag,
            "response action would trigger (logging-only implementation, no real effect)"
        );

        Ok(ResponseDecision::WouldExecute)
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
    fn applies_to_matching_tag() {
        let action = LoggingOnlyResponseAction::new("kill-on-reverse-shell", "suspected_reverse_shell");
        let event = event_with_tags(vec!["suspected_reverse_shell"]);
        assert!(action.applies_to(&event));
    }

    #[test]
    fn does_not_apply_without_matching_tag() {
        let action = LoggingOnlyResponseAction::new("kill-on-reverse-shell", "suspected_reverse_shell");
        let event = event_with_tags(vec!["some_other_tag"]);
        assert!(!action.applies_to(&event));
    }

    #[test]
    fn execute_returns_not_applicable_when_tag_missing() {
        let action = LoggingOnlyResponseAction::new("kill-on-reverse-shell", "suspected_reverse_shell");
        let event = event_with_tags(vec![]);
        let decision = action.execute(&event, true).unwrap();
        assert_eq!(decision, ResponseDecision::NotApplicable);
    }

    #[test]
    fn execute_returns_would_execute_when_applicable() {
        let action = LoggingOnlyResponseAction::new("kill-on-reverse-shell", "suspected_reverse_shell");
        let event = event_with_tags(vec!["suspected_reverse_shell"]);
        let decision = action.execute(&event, true).unwrap();
        assert_eq!(decision, ResponseDecision::WouldExecute);
    }

    #[test]
    fn logging_only_action_is_never_destructive() {
        let action = LoggingOnlyResponseAction::new("test", "tag");
        assert!(!action.is_destructive());
    }
}