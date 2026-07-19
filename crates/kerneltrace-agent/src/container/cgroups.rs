//! Lettura e parsing di `/proc/<pid>/cgroup`, punto di ingresso comune per
//! il riconoscimento di tutti i runtime container supportati.
//!
//! Il formato di `/proc/<pid>/cgroup` è una lista di righe
//! `hierarchy-ID:controller-list:cgroup-path`. Su cgroup v2 (unificato,
//! il default sui kernel moderni) c'è tipicamente una sola riga con
//! hierarchy-ID `0` e controller-list vuota. Il path della riga contiene
//! il pattern specifico del runtime (`docker/<id>`, `libpod-<id>`,
//! `kubepods...`), da cui deriviamo runtime e identificativo del
//! container.

use std::path::Path;

/// Legge il contenuto di `/proc/<pid>/cgroup` per un dato PID.
/// Isolata per permettere ai chiamanti di gestire l'assenza del processo
/// (terminato tra l'evento e la lettura) senza propagare un errore fatale.
pub fn read_cgroup_file(pid: u32) -> std::io::Result<String> {
    std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
}

/// Estrae il path di cgroup più specifico (l'ultima riga, tipicamente
/// quella della gerarchia unificata cgroup v2) dal contenuto grezzo di
/// `/proc/<pid>/cgroup`.
///
/// Funzione pura, testabile senza accesso reale al filesystem `/proc`.
pub fn extract_cgroup_path(contents: &str) -> Option<&str> {
    contents
        .lines()
        .filter_map(|line| line.rsplit(':').next())
        .filter(|path| !path.is_empty() && *path != "/")
        .last()
}

/// Verifica se un path assomiglia a un ID di container (stringa
/// esadecimale di lunghezza tipica 12 o 64 caratteri), usata dai parser
/// specifici per validare i match estratti dalle regex.
pub fn looks_like_container_id(candidate: &str) -> bool {
    let len = candidate.len();
    (len == 12 || len == 64) && candidate.chars().all(|c| c.is_ascii_hexdigit())
}

/// Ricava il path della directory `/sys/fs/cgroup` per un dato path di
/// cgroup, utile in futuro per letture aggiuntive (es. limiti di risorse)
/// senza dover ripetere la logica di composizione del path in più moduli.
pub fn cgroup_fs_path(cgroup_path: &str) -> std::path::PathBuf {
    Path::new("/sys/fs/cgroup").join(cgroup_path.trim_start_matches('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_last_nonempty_cgroup_path() {
        let contents = "0::/system.slice/docker-abc123.scope\n";
        assert_eq!(
            extract_cgroup_path(contents),
            Some("/system.slice/docker-abc123.scope")
        );
    }

    #[test]
    fn ignores_root_cgroup_path() {
        let contents = "0::/\n";
        assert_eq!(extract_cgroup_path(contents), None);
    }

    #[test]
    fn handles_multiple_hierarchy_lines() {
        let contents = "12:pids:/system.slice\n11:cpu:/system.slice\n0::/system.slice/docker-abc.scope\n";
        assert_eq!(
            extract_cgroup_path(contents),
            Some("/system.slice/docker-abc.scope")
        );
    }

    #[test]
    fn validates_container_id_length_and_charset() {
        assert!(looks_like_container_id(&"a".repeat(64)));
        assert!(looks_like_container_id(&"a".repeat(12)));
        assert!(!looks_like_container_id(&"a".repeat(10)));
        assert!(!looks_like_container_id("not-hex-chars-zzzz"));
    }
}