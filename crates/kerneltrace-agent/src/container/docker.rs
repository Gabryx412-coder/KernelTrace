//! Riconoscimento di container Docker a partire dal path di cgroup.
//!
//! Pattern osservati su host Docker moderni (cgroup v2, cgroupfs o
//! systemd driver):
//! - `/docker/<64-hex>` (cgroupfs driver)
//! - `/system.slice/docker-<64-hex>.scope` (systemd driver)

use once_cell::sync::Lazy;
use regex::Regex;

static DOCKER_CGROUPFS_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"/docker/([0-9a-f]{64})").expect("valid regex"));

static DOCKER_SYSTEMD_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"docker-([0-9a-f]{64})\.scope").expect("valid regex"));

/// Tenta di estrarre l'ID completo del container Docker da un path di
/// cgroup. Restituisce `None` se il path non corrisponde a nessun pattern
/// noto di Docker.
pub fn extract_docker_container_id(cgroup_path: &str) -> Option<String> {
    DOCKER_CGROUPFS_PATTERN
        .captures(cgroup_path)
        .or_else(|| DOCKER_SYSTEMD_PATTERN.captures(cgroup_path))
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_id_from_cgroupfs_pattern() {
        let path = format!("/docker/{}", "a".repeat(64));
        assert_eq!(extract_docker_container_id(&path), Some("a".repeat(64)));
    }

    #[test]
    fn extracts_id_from_systemd_pattern() {
        let path = format!("/system.slice/docker-{}.scope", "b".repeat(64));
        assert_eq!(extract_docker_container_id(&path), Some("b".repeat(64)));
    }

    #[test]
    fn returns_none_for_non_docker_path() {
        assert_eq!(extract_docker_container_id("/user.slice/user-1000.slice"), None);
    }

    #[test]
    fn returns_none_for_malformed_id_length() {
        let path = "/docker/tooShort";
        assert_eq!(extract_docker_container_id(path), None);
    }
}