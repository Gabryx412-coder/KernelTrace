//! Container awareness: riconoscimento automatico di Docker, Podman e
//! Kubernetes a partire dal cgroup del processo osservato, con
//! arricchimento del campo `container` di [`NormalizedEvent`].

pub mod cgroups;
pub mod docker;
pub mod kubernetes;
pub mod podman;

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use tracing::trace;

use crate::events::{ContainerContext, ContainerRuntime, Enricher, NormalizedEvent};

pub use kubernetes::KubernetesPodInfo;

/// Configurazione di quali runtime container tentare di riconoscere,
/// derivata da `ContainerSettings` (`config::schema`).
#[derive(Debug, Clone, Copy)]
pub struct ContainerResolverConfig {
    pub docker: bool,
    pub podman: bool,
    pub kubernetes: bool,
}

impl Default for ContainerResolverConfig {
    fn default() -> Self {
        Self {
            docker: true,
            podman: true,
            kubernetes: true,
        }
    }
}

/// Risolutore di container awareness: legge `/proc/<pid>/cgroup` e prova
/// i pattern di riconoscimento in ordine (Kubernetes prima, perché un pod
/// K8s contiene tipicamente anche un pattern containerd/CRI-O che
/// altrimenti potrebbe generare ambiguità con Docker "puro").
pub struct ContainerResolver {
    config: ContainerResolverConfig,
    /// Cache dei risultati per PID, per evitare di rileggere `/proc` a
    /// ogni singolo evento dello stesso processo (che nella stragrande
    /// maggioranza dei casi resta nello stesso container per tutta la sua
    /// vita). Il campo `None` cachato indica esplicitamente "processo non
    /// containerizzato", per evitare retry inutili sugli stessi PID.
    cache: RwLock<HashMap<u32, Option<ContainerContext>>>,
}

impl ContainerResolver {
    pub fn new(config: ContainerResolverConfig) -> Self {
        Self {
            config,
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Risolve il contesto container per un dato PID, usando la cache se
    /// disponibile.
    pub fn resolve(&self, pid: u32) -> Option<ContainerContext> {
        if let Some(cached) = self.cache.read().get(&pid) {
            return cached.clone();
        }

        let resolved = self.resolve_uncached(pid);
        self.cache.write().insert(pid, resolved.clone());
        resolved
    }

    fn resolve_uncached(&self, pid: u32) -> Option<ContainerContext> {
        let contents = cgroups::read_cgroup_file(pid).ok()?;
        let cgroup_path = cgroups::extract_cgroup_path(&contents)?;

        if self.config.kubernetes {
            if let Some(info) = kubernetes::extract_kubernetes_pod_info(cgroup_path) {
                return Some(ContainerContext {
                    runtime: ContainerRuntime::Kubernetes,
                    container_id: info
                        .container_id
                        .unwrap_or_else(|| info.pod_uid.clone()),
                    pod_name: Some(info.pod_uid),
                    namespace: None, // non derivabile dal solo cgroup path, vedi note nel modulo kubernetes
                });
            }
        }

        if self.config.docker {
            if let Some(id) = docker::extract_docker_container_id(cgroup_path) {
                return Some(ContainerContext {
                    runtime: ContainerRuntime::Docker,
                    container_id: id,
                    pod_name: None,
                    namespace: None,
                });
            }
        }

        if self.config.podman {
            if let Some(id) = podman::extract_podman_container_id(cgroup_path) {
                return Some(ContainerContext {
                    runtime: ContainerRuntime::Podman,
                    container_id: id,
                    pod_name: None,
                    namespace: None,
                });
            }
        }

        None
    }

    /// Rimuove un PID dalla cache, da chiamare quando un processo termina
    /// (es. agganciato allo scanner orfano/zombie di `process::lifecycle`
    /// in un miglioramento futuro) per evitare crescita illimitata della
    /// mappa interna su host con alto tasso di creazione processi.
    pub fn forget(&self, pid: u32) {
        self.cache.write().remove(&pid);
    }

    /// Numero di PID attualmente in cache (usato nei test).
    pub fn cache_len(&self) -> usize {
        self.cache.read().len()
    }
}

impl Enricher for ContainerResolver {
    fn enrich(&self, event: &mut NormalizedEvent) {
        event.container = self.resolve(event.process.pid);
        if event.container.is_some() {
            trace!(pid = event.process.pid, "container context resolved for event");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// I test end-to-end del resolver richiederebbero un vero `/proc/<pid>/cgroup`;
    /// la logica di parsing è già coperta a fondo nei singoli sotto-moduli
    /// (`docker`, `podman`, `kubernetes`, `cgroups`). Qui verifichiamo solo
    /// il comportamento della cache, che è specifico di questo modulo.

    #[test]
    fn forget_removes_pid_from_cache() {
        let resolver = ContainerResolver::new(ContainerResolverConfig::default());
        // Un PID quasi certamente inesistente non produce un contesto,
        // ma viene comunque cachato come `None`.
        let fake_pid = 999_999;
        let _ = resolver.resolve(fake_pid);
        assert_eq!(resolver.cache_len(), 1);

        resolver.forget(fake_pid);
        assert_eq!(resolver.cache_len(), 0);
    }

    #[test]
    fn resolve_caches_negative_result_for_nonexistent_process() {
        let resolver = ContainerResolver::new(ContainerResolverConfig::default());
        let fake_pid = 999_998;

        let first = resolver.resolve(fake_pid);
        let second = resolver.resolve(fake_pid);

        assert_eq!(first, None);
        assert_eq!(second, None);
        assert_eq!(resolver.cache_len(), 1);
    }

    #[test]
    fn config_can_disable_individual_runtimes() {
        let config = ContainerResolverConfig {
            docker: false,
            podman: false,
            kubernetes: false,
        };
        let resolver = ContainerResolver::new(config);
        assert!(!resolver.config.docker);
        assert!(!resolver.config.podman);
        assert!(!resolver.config.kubernetes);
    }
}