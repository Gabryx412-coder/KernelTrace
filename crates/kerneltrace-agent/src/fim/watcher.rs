//! Watcher del File Integrity Monitoring: collega gli eventi di file
//! normalizzati (Parte 6) alla baseline in memoria, taggando gli eventi
//! con le deviazioni rilevate affinché il rules engine (Parte 10) e gli
//! output sink (Parte 11) possano consumarle senza ricalcolare nulla.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tracing::{info, warn};

use crate::events::{Enricher, EventKind, EventPayload, NormalizedEvent};

use super::baseline::{Baseline, BaselineDeviation};

/// Tag applicati agli eventi in base alle deviazioni rilevate dal FIM,
/// consultabili dal rules engine e dagli output sink.
pub const TAG_FIM_CONTENT_CHANGED: &str = "fim_content_changed";
pub const TAG_FIM_PERMISSIONS_CHANGED: &str = "fim_permissions_changed";
pub const TAG_FIM_OWNER_CHANGED: &str = "fim_owner_changed";
pub const TAG_FIM_UNTRACKED_PATH: &str = "fim_untracked_path";

/// Componente che integra la baseline FIM nella pipeline eventi come
/// [`Enricher`], oltre a esporre l'inizializzazione della baseline stessa
/// a partire dai path configurati (`monitoring.fim_watch_paths`).
pub struct FimWatcher {
    baseline: Arc<Baseline>,
    /// Path esplicitamente monitorati; usato per decidere se un evento su
    /// un path non in `fim_watch_paths` va ignorato dal FIM (potrebbe
    /// comunque essere rilevante per altri moduli, es. detection engine
    /// su path sospetti come `/tmp`).
    watched_paths: Vec<PathBuf>,
}

impl FimWatcher {
    pub fn new(baseline: Arc<Baseline>, watched_paths: Vec<PathBuf>) -> Self {
        Self {
            baseline,
            watched_paths,
        }
    }

    /// Costruisce la baseline iniziale per tutti i path configurati,
    /// gestendo sia file singoli sia directory (registrate ricorsivamente).
    /// Da chiamare una sola volta all'avvio dell'agente, prima di
    /// collegare il watcher alla pipeline eventi.
    pub fn build_initial_baseline(&self) -> usize {
        let mut total = 0;
        for path in &self.watched_paths {
            let result = if path.is_dir() {
                self.baseline.register_recursive(path)
            } else {
                self.baseline.register(path).map(|()| 1)
            };

            match result {
                Ok(count) => {
                    info!(path = %path.display(), files = count, "FIM baseline built");
                    total += count;
                }
                Err(err) => {
                    warn!(path = %path.display(), error = %err, "failed to build FIM baseline for path");
                }
            }
        }
        total
    }

    /// Verifica se un path ricade sotto uno dei prefissi monitorati
    /// esplicitamente in configurazione.
    fn is_watched(&self, path: &Path) -> bool {
        self.watched_paths.iter().any(|watched| path.starts_with(watched))
    }

    fn tag_for_deviation(deviation: &BaselineDeviation) -> Option<&'static str> {
        match deviation {
            BaselineDeviation::ContentChanged { .. } => Some(TAG_FIM_CONTENT_CHANGED),
            BaselineDeviation::PermissionsChanged { .. } => Some(TAG_FIM_PERMISSIONS_CHANGED),
            BaselineDeviation::OwnerChanged { .. } => Some(TAG_FIM_OWNER_CHANGED),
            BaselineDeviation::NotBaselined => Some(TAG_FIM_UNTRACKED_PATH),
            // Un file rimosso e già assente dalla baseline (`forget` già
            // applicato altrove) non produce un tag aggiuntivo qui: la
            // rimozione della baseline stessa è gestita da `enrich` sugli
            // eventi di tipo FileDelete, vedi sotto.
            BaselineDeviation::Removed => None,
        }
    }
}

impl Enricher for FimWatcher {
    fn enrich(&self, event: &mut NormalizedEvent) {
        let EventPayload::File { path, .. } = &event.payload else {
            return;
        };

        let path_buf = PathBuf::from(path);

        if !self.is_watched(&path_buf) {
            return;
        }

        match event.event_kind {
            EventKind::FileDelete => {
                // Un'eliminazione di un file in baseline è di per sé
                // un'informazione rilevante per il rules engine (tramite
                // il tipo di evento `FileDelete` stesso); rimuoviamo il
                // path dalla baseline per non continuare a segnalare
                // deviazioni fantasma su un file che non esiste più.
                self.baseline.forget(&path_buf);
            }
            EventKind::FileRename => {
                // Il path originale non esiste più con questo nome;
                // rimuoviamo la vecchia voce. La nuova destinazione verrà
                // aggiunta alla baseline al prossimo evento di scrittura
                // rilevante, oppure può essere gestita esplicitamente da
                // un ri-scan periodico (miglioramento futuro).
                self.baseline.forget(&path_buf);
            }
            _ => {
                let deviations = self.baseline.check(&path_buf);
                for deviation in &deviations {
                    if let Some(tag) = Self::tag_for_deviation(deviation) {
                        event.tags.push(tag.to_string());
                    }
                }

                if !deviations.is_empty() {
                    warn!(
                        path = %path_buf.display(),
                        deviations = ?deviations,
                        "FIM baseline deviation detected"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::ProcessContext;
    use chrono::Utc;
    use uuid::Uuid;

    fn sample_event(path: &str, kind: EventKind) -> NormalizedEvent {
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
    fn tags_event_on_content_change() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut file, b"original").unwrap();

        let baseline = Arc::new(Baseline::new(super::super::hash::HashAlgorithm::Blake3));
        baseline.register(file.path()).unwrap();

        let watcher = FimWatcher::new(
            Arc::clone(&baseline),
            vec![file.path().parent().unwrap().to_path_buf()],
        );

        std::fs::write(file.path(), "tampered").unwrap();

        let mut event = sample_event(file.path().to_str().unwrap(), EventKind::FileChange);
        watcher.enrich(&mut event);

        assert!(event.tags.contains(&TAG_FIM_CONTENT_CHANGED.to_string()));
    }

    #[test]
    fn ignores_events_outside_watched_paths() {
        let baseline = Arc::new(Baseline::new(super::super::hash::HashAlgorithm::Blake3));
        let watcher = FimWatcher::new(baseline, vec![PathBuf::from("/opt/watched")]);

        let mut event = sample_event("/tmp/unwatched/file", EventKind::FileChange);
        watcher.enrich(&mut event);

        assert!(event.tags.is_empty());
    }

    #[test]
    fn delete_event_removes_baseline_entry() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut file, b"content").unwrap();

        let baseline = Arc::new(Baseline::new(super::super::hash::HashAlgorithm::Blake3));
        baseline.register(file.path()).unwrap();
        assert_eq!(baseline.len(), 1);

        let watcher = FimWatcher::new(
            Arc::clone(&baseline),
            vec![file.path().parent().unwrap().to_path_buf()],
        );

        let mut event = sample_event(file.path().to_str().unwrap(), EventKind::FileDelete);
        watcher.enrich(&mut event);

        assert!(baseline.is_empty());
    }

    #[test]
    fn untracked_path_within_watched_dir_is_tagged() {
        let dir = tempfile::tempdir().unwrap();
        let untracked_path = dir.path().join("new_file.txt");
        std::fs::write(&untracked_path, "new").unwrap();

        let baseline = Arc::new(Baseline::new(super::super::hash::HashAlgorithm::Blake3));
        let watcher = FimWatcher::new(Arc::clone(&baseline), vec![dir.path().to_path_buf()]);

        let mut event = sample_event(untracked_path.to_str().unwrap(), EventKind::FileOpen);
        watcher.enrich(&mut event);

        assert!(event.tags.contains(&TAG_FIM_UNTRACKED_PATH.to_string()));
    }
}