//! Integration test del File Integrity Monitoring: verifica che
//! `Baseline` e `FimWatcher` collaborino correttamente per rilevare
//! modifiche di contenuto e permessi su file reali su disco.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use chrono::Utc;
use kerneltrace_agent::events::{Enricher, EventKind, EventPayload, NormalizedEvent, ProcessContext};
use kerneltrace_agent::fim::{Baseline, FimWatcher, HashAlgorithm, TAG_FIM_CONTENT_CHANGED, TAG_FIM_PERMISSIONS_CHANGED};
use uuid::Uuid;

fn file_event(path: &str, kind: EventKind) -> NormalizedEvent {
    NormalizedEvent {
        id: Uuid::new_v4(),
        timestamp: Utc::now(),
        event_kind: kind,
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
        payload: EventPayload::File {
            path: path.to_string(),
            new_path: None,
            open_flags: 0,
            mode: None,
            new_owner_uid: None,
            new_owner_gid: None,
        },
        container: None,
        tags: Vec::new(),
    }
}

#[test]
fn detects_content_and_permission_changes_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("critical.conf");
    {
        let mut file = std::fs::File::create(&file_path).unwrap();
        write!(file, "original configuration").unwrap();
    }

    let baseline = Arc::new(Baseline::new(HashAlgorithm::Blake3));
    let watcher = FimWatcher::new(Arc::clone(&baseline), vec![dir.path().to_path_buf()]);

    let registered = watcher.build_initial_baseline();
    assert_eq!(registered, 1);

    // Nessuna deviazione finché il file resta invariato.
    let mut unchanged_event = file_event(file_path.to_str().unwrap(), EventKind::FileOpen);
    watcher.enrich(&mut unchanged_event);
    assert!(unchanged_event.tags.is_empty());

    // Modifica del contenuto: deve essere rilevata.
    std::fs::write(&file_path, "TAMPERED configuration").unwrap();
    let mut changed_event = file_event(file_path.to_str().unwrap(), EventKind::FileChange);
    watcher.enrich(&mut changed_event);
    assert!(changed_event.tags.contains(&TAG_FIM_CONTENT_CHANGED.to_string()));

    // Rifreschiamo la baseline (simula un'accettazione operativa della
    // modifica) e verifichiamo che non venga più segnalata.
    baseline.refresh(&file_path).unwrap();
    let mut refreshed_event = file_event(file_path.to_str().unwrap(), EventKind::FileOpen);
    watcher.enrich(&mut refreshed_event);
    assert!(refreshed_event.tags.is_empty());

    // Modifica dei permessi: deve essere rilevata indipendentemente dal
    // contenuto.
    std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o777)).unwrap();
    let mut perm_event = file_event(file_path.to_str().unwrap(), EventKind::FileChange);
    watcher.enrich(&mut perm_event);
    assert!(perm_event.tags.contains(&TAG_FIM_PERMISSIONS_CHANGED.to_string()));
}

#[test]
fn delete_event_removes_path_from_baseline() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("temp.txt");
    std::fs::write(&file_path, "content").unwrap();

    let baseline = Arc::new(Baseline::new(HashAlgorithm::Blake3));
    baseline.register(&file_path).unwrap();
    assert_eq!(baseline.len(), 1);

    let watcher = FimWatcher::new(Arc::clone(&baseline), vec![dir.path().to_path_buf()]);

    let mut delete_event = file_event(file_path.to_str().unwrap(), EventKind::FileDelete);
    watcher.enrich(&mut delete_event);

    assert!(baseline.is_empty());
}