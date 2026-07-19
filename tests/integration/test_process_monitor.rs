//! Integration test del process monitoring: verifica che `ProcessTree`,
//! `ProcessTreeEnricher` e le funzioni pure di `process::lifecycle`
//! collaborino correttamente end-to-end, esercitando l'API pubblica del
//! crate `kerneltrace-agent` esattamente come farebbe la pipeline reale.

use std::sync::Arc;

use chrono::Utc;
use kerneltrace_agent::events::{Enricher, EventKind, EventPayload, NormalizedEvent, ProcessContext};
use kerneltrace_agent::process::{is_orphaned, ProcessTree, ProcessTreeEnricher};
use uuid::Uuid;

fn lifecycle_event(pid: u32, ppid: u32, comm: &str) -> NormalizedEvent {
    NormalizedEvent {
        id: Uuid::new_v4(),
        timestamp: Utc::now(),
        event_kind: EventKind::ProcessLifecycle,
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
        payload: EventPayload::ProcessLifecycle {
            syscall: "clone".to_string(),
            exit_code: None,
            is_orphan: false,
            is_zombie: false,
        },
        container: None,
        tags: Vec::new(),
    }
}

fn exec_event(pid: u32) -> NormalizedEvent {
    NormalizedEvent {
        id: Uuid::new_v4(),
        timestamp: Utc::now(),
        event_kind: EventKind::Exec,
        process: ProcessContext {
            pid,
            tgid: pid,
            ppid: 0, // deliberatamente assente: la probe eBPF non lo popola (vedi Parte 3)
            uid: 1000,
            gid: 1000,
            comm: "sh".to_string(),
            cgroup_id: 0,
            parent_comm: None,
        },
        payload: EventPayload::Exec {
            filename: "/bin/sh".to_string(),
            args: vec![],
        },
        container: None,
        tags: Vec::new(),
    }
}

#[test]
fn process_tree_resolves_ppid_and_parent_comm_across_events() {
    let tree = Arc::new(ProcessTree::new());
    let enricher = ProcessTreeEnricher::new(Arc::clone(&tree));

    // 1. Un evento di fork registra la relazione parent-child nel tree.
    let mut fork_event = lifecycle_event(2000, 1000, "bash");
    enricher.enrich(&mut fork_event);

    let mut parent_event = lifecycle_event(1000, 1, "sshd");
    enricher.enrich(&mut parent_event);

    // 2. Un evento di exec successivo, con ppid non popolato dalla probe
    // eBPF (comportamento reale, vedi kerneltrace-ebpf::probes::process),
    // deve ricevere sia il ppid corretto sia il nome del padre risolti dal
    // process tree.
    let mut exec = exec_event(2000);
    enricher.enrich(&mut exec);

    assert_eq!(exec.process.ppid, 1000);
    assert_eq!(exec.process.parent_comm.as_deref(), Some("bash"));
}

#[test]
fn process_tree_ancestry_walks_multiple_generations() {
    let tree = ProcessTree::new();
    tree.record(300, 200, "make");
    tree.record(200, 100, "bash");
    tree.record(100, 1, "sshd");

    let ancestry = tree.ancestry(300, 10);
    assert_eq!(ancestry, vec![200, 100, 1]);
}

#[test]
fn orphan_detection_matches_expected_semantics() {
    // Un processo il cui ppid osservato in /proc è diventato 1 (init),
    // pur essendo stato originariamente figlio di un altro processo, è
    // considerato orfano riassegnato.
    assert!(is_orphaned(500, 1));
    // Un processo il cui genitore originale era già init non è
    // "diventato" orfano: la sua condizione non è cambiata.
    assert!(!is_orphaned(1, 1));
}