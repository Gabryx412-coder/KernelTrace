//! Riconoscimento di pod Kubernetes a partire dal path di cgroup.
//!
//! Kubernetes organizza i cgroup sotto `kubepods` (cgroupfs driver) o
//! `kubepods.slice` (systemd driver), con una struttura annidata per
//! classe di QoS (`burstable`, `besteffort`, o nessuna per `guaranteed`) e
//! per pod (`pod<uid>`). All'interno del cgroup del pod si trova poi il
//! cgroup del singolo container, gestito dal container runtime
//! sottostante (containerd: `cri-containerd-<id>.scope`; CRI-O:
//! `crio-<id>.scope`).
//!
//! Il nome del pod e il namespace Kubernetes **non sono derivabili dal
//! solo path di cgroup** (che contiene l'UID del pod, non il suo nome
//! leggibile): la risoluzione completa richiederebbe una query al
//! Kubelet API locale (`https://localhost:10250/pods`) o al CRI runtime,
//! prevista come miglioramento futuro (vedi `ROADMAP.md`). Per questa
//! implementazione popoliamo `container_id` e l'UID del pod come
//! `pod_name` provvisorio, chiaramente distinguibile da un nome reale
//! per via del formato UUID.

use once_cell::sync::Lazy;
use regex::Regex;

/// Cattura l'UID del pod, sia nel formato con trattini (cgroupfs) sia nel
/// formato con underscore (systemd, dove i trattini dell'UUID vengono
/// sostituiti da underscore all'interno del nome dello slice).
static POD_UID_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"kubepods[^/]*pod([0-9a-f_\-]{32,36})").expect("valid regex")
});

/// Cattura l'ID del container gestito dal runtime CRI sottostante
/// (containerd o CRI-O).
static CRI_CONTAINER_ID_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:cri-containerd|crio)-([0-9a-f]{64})").expect("valid regex")
});

/// Normalizza un UID di pod nel formato systemd (underscore) al formato
/// UUID standard con trattini, per coerenza indipendentemente dal driver
/// cgroup in uso.
fn normalize_pod_uid(raw: &str) -> String {
    // Il formato systemd usa underscore al posto dei trattini in
    // posizioni fisse (8-4-4-4-12); se il raw contiene già trattini
    // (cgroupfs driver) lo restituiamo invariato.
    if raw.contains('-') {
        raw.to_string()
    } else if raw.len() == 32 {
        format!(
            "{}-{}-{}-{}-{}",
            &raw[0..8],
            &raw[8..12],
            &raw[12..16],
            &raw[16..20],
            &raw[20..32]
        )
    } else {
        raw.to_string()
    }
}

/// Informazioni estratte dal path di cgroup relative a un pod Kubernetes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KubernetesPodInfo {
    /// UID del pod (garantito derivabile dal cgroup path).
    pub pod_uid: String,
    /// ID del container gestito dal runtime CRI, se presente nello stesso
    /// path (potrebbe essere assente se si sta osservando un processo a
    /// livello di pod ma non ancora attribuito a un container specifico).
    pub container_id: Option<String>,
}

/// Tenta di riconoscere un path di cgroup come appartenente a un pod
/// Kubernetes, estraendo UID del pod ed eventuale ID container CRI.
pub fn extract_kubernetes_pod_info(cgroup_path: &str) -> Option<KubernetesPodInfo> {
    if !cgroup_path.contains("kubepods") {
        return None;
    }

    let pod_uid = POD_UID_PATTERN
        .captures(cgroup_path)
        .and_then(|caps| caps.get(1))
        .map(|m| normalize_pod_uid(m.as_str()))?;

    let container_id = CRI_CONTAINER_ID_PATTERN
        .captures(cgroup_path)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_string());

    Some(KubernetesPodInfo {
        pod_uid,
        container_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_pod_uid_cgroupfs_driver() {
        let path = "/kubepods/burstable/pod12345678-1234-1234-1234-123456789012/containerd-abcdef.scope";
        let info = extract_kubernetes_pod_info(path).unwrap();
        assert_eq!(info.pod_uid, "12345678-1234-1234-1234-123456789012");
    }

    #[test]
    fn extracts_pod_uid_systemd_driver_with_underscores() {
        let path = "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod12345678_1234_1234_1234_123456789012.slice";
        let info = extract_kubernetes_pod_info(path).unwrap();
        assert_eq!(info.pod_uid, "12345678-1234-1234-1234-123456789012");
    }

    #[test]
    fn extracts_cri_containerd_container_id() {
        let container_id = "a".repeat(64);
        let path = format!(
            "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod12345678_1234_1234_1234_123456789012.slice/cri-containerd-{container_id}.scope"
        );
        let info = extract_kubernetes_pod_info(&path).unwrap();
        assert_eq!(info.container_id, Some(container_id));
    }

    #[test]
    fn extracts_crio_container_id() {
        let container_id = "b".repeat(64);
        let path = format!(
            "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod00000000_0000_0000_0000_000000000000.slice/crio-{container_id}.scope"
        );
        let info = extract_kubernetes_pod_info(&path).unwrap();
        assert_eq!(info.container_id, Some(container_id));
    }

    #[test]
    fn returns_none_for_non_kubernetes_path() {
        assert_eq!(extract_kubernetes_pod_info("/docker/abcdef"), None);
    }

    #[test]
    fn pod_without_container_id_still_recognized() {
        let path = "/kubepods/burstable/pod12345678-1234-1234-1234-123456789012";
        let info = extract_kubernetes_pod_info(path).unwrap();
        assert_eq!(info.container_id, None);
    }
}