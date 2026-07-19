//! Process tree: relazioni parent-child tra i processi osservati.
//!
//! Il tracepoint `sched_process_exec` non espone il PID del processo padre
//! nel proprio formato (vedi note in `kerneltrace-ebpf::probes::process`);
//! questo modulo colma il vuoto mantenendo in memoria, lato userspace, la
//! mappa pid -> ppid costruita a partire dagli eventi di fork/clone/vfork,
//! e la usa per risolvere il PPID mancante sugli eventi di exec, oltre a
//! risolvere il nome del processo padre (`parent_comm`), usato dal rules
//! engine (Parte 10) per regole come "shell spawnata da nginx".

use std::collections::HashMap;

use parking_lot::RwLock;
use tracing::trace;

use crate::events::{Enricher, EventKind, EventPayload, NormalizedEvent};

/// Nodo del process tree: stato minimo necessario per la risoluzione del
/// PPID, del nome del processo padre, e per il rilevamento di processi
/// orfani (modulo `lifecycle`).
#[derive(Debug, Clone)]
pub struct ProcessNode {
    pub pid: u32,
    pub ppid: u32,
    pub comm: String,
}

/// Process tree condiviso, aggiornato in tempo reale dagli eventi di
/// ciclo di vita del processo e consultato per arricchire altri eventi.
///
/// Usa `parking_lot::RwLock` anziché `std::sync::RwLock` per lock più
/// leggeri (nessun poisoning, footprint di memoria inferiore), coerente
/// con l'obiettivo di overhead minimo dell'agente.
#[derive(Default)]
pub struct ProcessTree {
    nodes: RwLock<HashMap<u32, ProcessNode>>,
}

impl ProcessTree {
    pub fn new() -> Self {
        Self {
            nodes: RwLock::new(HashMap::new()),
        }
    }

    /// Registra (o aggiorna) un processo nel tree, tipicamente in risposta
    /// a un evento `ProcessLifecycle` con syscall `clone`/`fork`/`vfork`.
    pub fn record(&self, pid: u32, ppid: u32, comm: &str) {
        let mut nodes = self.nodes.write();
        nodes.insert(
            pid,
            ProcessNode {
                pid,
                ppid,
                comm: comm.to_string(),
            },
        );
        trace!(pid, ppid, comm, "process tree: node recorded");
    }

    /// Rimuove un processo dal tree, tipicamente alla sua terminazione.
    pub fn remove(&self, pid: u32) -> Option<ProcessNode> {
        self.nodes.write().remove(&pid)
    }

    /// Risolve il PPID di un processo noto al tree; `None` se il processo
    /// non è mai stato osservato tramite un evento di fork.
    pub fn resolve_ppid(&self, pid: u32) -> Option<u32> {
        self.nodes.read().get(&pid).map(|n| n.ppid)
    }

    /// Risolve il nome (`comm`) di un processo noto al tree, usato per
    /// popolare `ProcessContext::parent_comm` sugli eventi `exec` (Parte 10,
    /// necessario per regole come "bash spawnata da nginx").
    pub fn comm_of(&self, pid: u32) -> Option<String> {
        self.nodes.read().get(&pid).map(|n| n.comm.clone())
    }

    /// Restituisce la catena di antenati di un processo, dal genitore
    /// diretto fino alla radice conosciuta, limitata a `max_depth` per
    /// evitare loop in caso di dati inconsistenti (es. cicli spuri dovuti
    /// a eventi persi).
    pub fn ancestry(&self, pid: u32, max_depth: usize) -> Vec<u32> {
        let nodes = self.nodes.read();
        let mut result = Vec::new();
        let mut current = pid;

        for _ in 0..max_depth {
            match nodes.get(&current) {
                Some(node) if node.ppid != 0 && node.ppid != current => {
                    result.push(node.ppid);
                    current = node.ppid;
                }
                _ => break,
            }
        }

        result
    }

    /// Istantanea dei PID attualmente tracciati, usata dallo scanner
    /// periodico orfano/zombie (`lifecycle::OrphanZombieScanner`) per
    /// evitare di tenere il lock durante letture I/O su `/proc`.
    pub fn snapshot_pids(&self) -> Vec<u32> {
        self.nodes.read().keys().copied().collect()
    }

    /// Numero di processi attualmente tracciati (usato nei test e in
    /// eventuali metriche di diagnostica).
    pub fn len(&self) -> usize {
        self.nodes.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Arricchitore che mantiene aggiornato il [`ProcessTree`] e risolve, sugli
/// eventi di `exec`:
/// - il PPID mancante (la probe eBPF non può popolarlo direttamente in
///   kernel-space, vedi limiti del formato del tracepoint `sched_process_exec`);
/// - il nome del processo padre (`parent_comm`), usato dal rules engine
///   per regole basate sul processo genitore.
pub struct ProcessTreeEnricher {
    tree: std::sync::Arc<ProcessTree>,
}

impl ProcessTreeEnricher {
    pub fn new(tree: std::sync::Arc<ProcessTree>) -> Self {
        Self { tree }
    }
}

impl Enricher for ProcessTreeEnricher {
    fn enrich(&self, event: &mut NormalizedEvent) {
        match event.event_kind {
            EventKind::ProcessLifecycle => {
                if let EventPayload::ProcessLifecycle { .. } = &event.payload {
                    self.tree
                        .record(event.process.pid, event.process.ppid, &event.process.comm);
                }
            }
            EventKind::Exec => {
                if event.process.ppid == 0 {
                    if let Some(ppid) = self.tree.resolve_ppid(event.process.pid) {
                        event.process.ppid = ppid;
                    }
                }
                if event.process.ppid != 0 {
                    event.process.parent_comm = self.tree.comm_of(event.process.ppid);
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_and_resolves_ppid() {
        let tree = ProcessTree::new();
        tree.record(200, 100, "bash");

        assert_eq!(tree.resolve_ppid(200), Some(100));
        assert_eq!(tree.resolve_ppid(999), None);
    }

    #[test]
    fn resolves_comm_of_known_pid() {
        let tree = ProcessTree::new();
        tree.record(100, 1, "nginx");

        assert_eq!(tree.comm_of(100), Some("nginx".to_string()));
        assert_eq!(tree.comm_of(999), None);
    }

    #[test]
    fn ancestry_walks_up_to_root() {
        let tree = ProcessTree::new();
        tree.record(300, 200, "sh");
        tree.record(200, 100, "bash");
        tree.record(100, 1, "sshd");

        let ancestry = tree.ancestry(300, 10);
        assert_eq!(ancestry, vec![200, 100, 1]);
    }

    #[test]
    fn ancestry_respects_max_depth() {
        let tree = ProcessTree::new();
        tree.record(300, 200, "sh");
        tree.record(200, 100, "bash");
        tree.record(100, 1, "sshd");

        let ancestry = tree.ancestry(300, 1);
        assert_eq!(ancestry, vec![200]);
    }

    #[test]
    fn remove_drops_node() {
        let tree = ProcessTree::new();
        tree.record(400, 1, "curl");
        assert_eq!(tree.len(), 1);

        let removed = tree.remove(400);
        assert!(removed.is_some());
        assert!(tree.is_empty());
    }

    #[test]
    fn snapshot_pids_reflects_current_state() {
        let tree = ProcessTree::new();
        tree.record(1, 0, "init");
        tree.record(2, 1, "sshd");

        let mut pids = tree.snapshot_pids();
        pids.sort_unstable();
        assert_eq!(pids, vec![1, 2]);
    }
}