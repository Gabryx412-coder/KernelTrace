//! Benchmark del rules engine: misura il costo di valutazione di un
//! evento contro l'intero set di regole built-in, per quantificare
//! l'overhead introdotto dal detection engine al crescere del numero di
//! regole caricate.

use std::path::PathBuf;

use chrono::Utc;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use kerneltrace_agent::detection::{load_rules_from_directory, DetectionEngine};
use kerneltrace_agent::events::{Enricher, EventKind, EventPayload, NormalizedEvent, ProcessContext};
use uuid::Uuid;

fn builtin_rules_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("crates")
        .join("kerneltrace-agent")
        .join("src")
        .join("detection")
        .join("builtin_rules")
}

fn benign_exec_event() -> NormalizedEvent {
    NormalizedEvent {
        id: Uuid::new_v4(),
        timestamp: Utc::now(),
        event_kind: EventKind::Exec,
        process: ProcessContext {
            pid: 1000,
            tgid: 1000,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            comm: "ls".to_string(),
            cgroup_id: 0,
            parent_comm: Some("bash".to_string()),
        },
        payload: EventPayload::Exec {
            filename: "/usr/bin/ls".to_string(),
            args: vec!["-la".to_string(), "/home/user".to_string()],
        },
        container: None,
        tags: Vec::new(),
    }
}

fn bench_detection_engine_benign_event(c: &mut Criterion) {
    let rules = load_rules_from_directory(&builtin_rules_dir(), true)
        .expect("builtin rules must load for benchmark");
    let engine = DetectionEngine::new(rules);

    c.bench_function("detection_engine_evaluate_benign_event", |b| {
        b.iter(|| {
            let mut event = benign_exec_event();
            engine.enrich(&mut event);
            black_box(event);
        })
    });
}

criterion_group!(benches, bench_detection_engine_benign_event);
criterion_main!(benches);