//! Baseline del File Integrity Monitoring: snapshot in memoria di
//! metadati e hash dei path monitorati, usato per rilevare deviazioni
//! (modifiche di contenuto, permessi o owner) rispetto allo stato noto.

use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use parking_lot::RwLock;
use tracing::{debug, warn};

use crate::error::AgentResult;

use super::hash::{hash_file, HashAlgorithm};

/// Snapshot dei metadati e dell'hash di un singolo file monitorato al
/// momento della sua registrazione in baseline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileBaselineEntry {
    pub size: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: i64,
    pub hash: String,
}

/// Tipo di deviazione rilevata confrontando lo stato corrente di un file
/// con la sua baseline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BaselineDeviation {
    ContentChanged { old_hash: String, new_hash: String },
    PermissionsChanged { old_mode: u32, new_mode: u32 },
    OwnerChanged {
        old_uid: u32,
        new_uid: u32,
        old_gid: u32,
        new_gid: u32,
    },
    /// Il file era in baseline ma non esiste più sul filesystem.
    Removed,
    /// Il file non è (ancora) presente in baseline: non è necessariamente
    /// un'anomalia (potrebbe essere stato appena creato legittimamente),
    /// ma va segnalato al chiamante perché lo valuti nel contesto delle
    /// regole di detection.
    NotBaselined,
}

/// Baseline in memoria dei path monitorati dal File Integrity Monitoring.
///
/// Usa `parking_lot::RwLock` per letture concorrenti a basso overhead
/// durante la valutazione degli eventi (molteplici letture per ogni
/// evento di file, scritture solo su ri-baseline esplicita o dopo una
/// modifica confermata).
#[derive(Default)]
pub struct Baseline {
    entries: RwLock<HashMap<PathBuf, FileBaselineEntry>>,
    algorithm: HashAlgorithm,
}

impl Baseline {
    pub fn new(algorithm: HashAlgorithm) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            algorithm,
        }
    }

    /// Calcola e registra la baseline per un singolo path. Da chiamare in
    /// fase di avvio dell'agente per ogni path in
    /// `monitoring.fim_watch_paths`, e nuovamente dopo una modifica
    /// confermata come legittima (per non continuare a segnalarla).
    pub fn register(&self, path: &Path) -> AgentResult<()> {
        let entry = build_entry(path, self.algorithm)?;
        self.entries.write().insert(path.to_path_buf(), entry);
        debug!(path = %path.display(), "registered file in FIM baseline");
        Ok(())
    }

    /// Registra ricorsivamente tutti i file sotto una directory. I
    /// sottoerrori (es. permessi insufficienti su un singolo file) vengono
    /// loggati come warning e non interrompono la scansione degli altri
    /// file: un singolo file non leggibile non deve impedire di
    /// costruire la baseline per il resto dell'albero.
    pub fn register_recursive(&self, root: &Path) -> AgentResult<usize> {
        let mut count = 0;
        for entry in walk_files(root) {
            match self.register(&entry) {
                Ok(()) => count += 1,
                Err(err) => {
                    warn!(path = %entry.display(), error = %err, "failed to register file in FIM baseline, skipping");
                }
            }
        }
        Ok(count)
    }

    /// Confronta lo stato corrente di un path con la baseline registrata,
    /// restituendo l'elenco delle deviazioni rilevate (vuoto se il file è
    /// invariato).
    pub fn check(&self, path: &Path) -> Vec<BaselineDeviation> {
        let baseline_entry = self.entries.read().get(path).cloned();

        let Some(baseline_entry) = baseline_entry else {
            return vec![BaselineDeviation::NotBaselined];
        };

        let current_entry = match build_entry(path, self.algorithm) {
            Ok(entry) => entry,
            Err(_) => return vec![BaselineDeviation::Removed],
        };

        let mut deviations = Vec::new();

        if current_entry.hash != baseline_entry.hash {
            deviations.push(BaselineDeviation::ContentChanged {
                old_hash: baseline_entry.hash.clone(),
                new_hash: current_entry.hash.clone(),
            });
        }

        if current_entry.mode != baseline_entry.mode {
            deviations.push(BaselineDeviation::PermissionsChanged {
                old_mode: baseline_entry.mode,
                new_mode: current_entry.mode,
            });
        }

        if current_entry.uid != baseline_entry.uid || current_entry.gid != baseline_entry.gid {
            deviations.push(BaselineDeviation::OwnerChanged {
                old_uid: baseline_entry.uid,
                new_uid: current_entry.uid,
                old_gid: baseline_entry.gid,
                new_gid: current_entry.gid,
            });
        }

        deviations
    }

    /// Aggiorna la baseline di un path dopo che una modifica è stata
    /// valutata (es. accettata come legittima dal rules engine), evitando
    /// di continuare a segnalare la stessa deviazione a ogni evento
    /// successivo.
    pub fn refresh(&self, path: &Path) -> AgentResult<()> {
        self.register(path)
    }

    /// Rimuove un path dalla baseline, tipicamente in risposta a un
    /// evento di eliminazione file confermato.
    pub fn forget(&self, path: &Path) {
        self.entries.write().remove(path);
    }

    /// Numero di file attualmente in baseline.
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn build_entry(path: &Path, algorithm: HashAlgorithm) -> AgentResult<FileBaselineEntry> {
    let metadata = std::fs::metadata(path).map_err(crate::error::AgentError::Io)?;
    let hash = hash_file(path, algorithm)?;

    Ok(FileBaselineEntry {
        size: metadata.len(),
        mode: metadata.mode(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        mtime: metadata.mtime(),
        hash,
    })
}

/// Itera ricorsivamente tutti i file (non directory) sotto `root`.
/// Le sotto-directory non leggibili vengono silenziosamente saltate: la
/// gestione degli errori a livello di singolo file avviene nel chiamante
/// (`register_recursive`).
fn walk_files(root: &Path) -> Vec<PathBuf> {
    let mut result = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let Ok(read_dir) = std::fs::read_dir(&dir) else {
            continue;
        };

        for entry in read_dir.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.is_file() {
                result.push(path);
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn register_and_check_unchanged_file() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        write!(file, "original content").unwrap();
        file.flush().unwrap();

        let baseline = Baseline::new(HashAlgorithm::Blake3);
        baseline.register(file.path()).unwrap();

        let deviations = baseline.check(file.path());
        assert!(deviations.is_empty());
    }

    #[test]
    fn detects_content_change() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        write!(file, "original content").unwrap();
        file.flush().unwrap();

        let baseline = Baseline::new(HashAlgorithm::Blake3);
        baseline.register(file.path()).unwrap();

        // Modifichiamo il contenuto dopo la registrazione in baseline.
        std::fs::write(file.path(), "tampered content").unwrap();

        let deviations = baseline.check(file.path());
        assert!(deviations
            .iter()
            .any(|d| matches!(d, BaselineDeviation::ContentChanged { .. })));
    }

    #[test]
    fn detects_permission_change() {
        use std::os::unix::fs::PermissionsExt;

        let mut file = tempfile::NamedTempFile::new().unwrap();
        write!(file, "content").unwrap();
        file.flush().unwrap();

        let baseline = Baseline::new(HashAlgorithm::Blake3);
        baseline.register(file.path()).unwrap();

        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o777)).unwrap();

        let deviations = baseline.check(file.path());
        assert!(deviations
            .iter()
            .any(|d| matches!(d, BaselineDeviation::PermissionsChanged { .. })));
    }

    #[test]
    fn unbaselined_path_reports_not_baselined() {
        let baseline = Baseline::new(HashAlgorithm::Blake3);
        let deviations = baseline.check(Path::new("/tmp/never-registered-kerneltrace-test"));
        assert_eq!(deviations, vec![BaselineDeviation::NotBaselined]);
    }

    #[test]
    fn removed_file_reports_removed() {
        let path = {
            let file = tempfile::NamedTempFile::new().unwrap();
            file.path().to_path_buf()
        };
        // Il file esiste temporaneamente durante la registrazione...
        std::fs::write(&path, "content").unwrap();

        let baseline = Baseline::new(HashAlgorithm::Blake3);
        baseline.register(&path).unwrap();

        // ...poi viene rimosso prima del controllo.
        std::fs::remove_file(&path).unwrap();

        let deviations = baseline.check(&path);
        assert_eq!(deviations, vec![BaselineDeviation::Removed]);
    }

    #[test]
    fn refresh_clears_previously_detected_deviation() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        write!(file, "v1").unwrap();
        file.flush().unwrap();

        let baseline = Baseline::new(HashAlgorithm::Blake3);
        baseline.register(file.path()).unwrap();

        std::fs::write(file.path(), "v2").unwrap();
        assert!(!baseline.check(file.path()).is_empty());

        baseline.refresh(file.path()).unwrap();
        assert!(baseline.check(file.path()).is_empty());
    }

    #[test]
    fn forget_removes_entry_from_baseline() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        write!(file, "content").unwrap();
        file.flush().unwrap();

        let baseline = Baseline::new(HashAlgorithm::Blake3);
        baseline.register(file.path()).unwrap();
        assert_eq!(baseline.len(), 1);

        baseline.forget(file.path());
        assert!(baseline.is_empty());
    }

    #[test]
    fn register_recursive_finds_nested_files() {
        let dir = tempfile::tempdir().unwrap();
        let nested_dir = dir.path().join("nested");
        std::fs::create_dir(&nested_dir).unwrap();
        std::fs::write(dir.path().join("top.txt"), "a").unwrap();
        std::fs::write(nested_dir.join("inner.txt"), "b").unwrap();

        let baseline = Baseline::new(HashAlgorithm::Blake3);
        let count = baseline.register_recursive(dir.path()).unwrap();

        assert_eq!(count, 2);
        assert_eq!(baseline.len(), 2);
    }
}