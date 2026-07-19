//! Riconoscimento di container Podman a partire dal path di cgroup.
//!
//! Pattern osservati:
//! - `/libpod-<64-hex>` (cgroupfs driver, o rootless senza systemd)
//! - `.../libpod-conmon-<64-hex>.scope` (processo conmon associato)
//! - `machine.slice/libpod-<64-hex>.scope` (systemd driver)
//!
//! Escludiamo deliberatamente i cgroup di `conmon` dal risultato finale
//! come "container id primario": `conmon` è il processo di supervisione
//! di Podman, non il container stesso, ma il suo cgroup contiene comunque
//! l'ID del container a cui è associato, utile quando la probe osserva il
//! processo conmon anziché un processo dentro al container.

use once_cell::sync::Lazy;
use regex::Regex;

static PODMAN_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"libpod(?:-conmon)?-([0-9a-f]{64})\.scope").expect("valid regex"));

static PODMAN_CGROUPFS_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"/libpod-([0-9a-f]{64})(?:/|$)").expect("valid regex"));

/// Tenta di estrarre l'ID completo del container Podman da un path di
/// cgroup.
pub fn extract_podman_container_id(cgroup_path: &str) -> Option<String> {
    PODMAN_PATTERN
        .captures(cgroup_path)
        .or_else(|| PODMAN_CGROUPFS_PATTERN.captures(cgroup_path))
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_id_from_systemd_scope() {
        let path = format!("/machine.slice/libpod-{}.scope", "c".repeat(64));
        assert_eq!(extract_podman_container_id(&path), Some("c".repeat(64)));
    }

    #[test]
    fn extracts_id_from_conmon_scope() {
        let path = format!("/machine.slice/libpod-conmon-{}.scope", "d".repeat(64));
        assert_eq!(extract_podman_container_id(&path), Some("d".repeat(64)));
    }

    #[test]
    fn extracts_id_from_cgroupfs_pattern() {
        let path = format!("/libpod-{}/", "e".repeat(64));
        assert_eq!(extract_podman_container_id(&path), Some("e".repeat(64)));
    }

    #[test]
    fn returns_none_for_non_podman_path() {
        assert_eq!(extract_podman_container_id("/docker/abcdef"), None);
    }
}