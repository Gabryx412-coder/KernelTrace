//! Rilevamento di processi orfani e zombie.
//!
//! A differenza dell'arricchimento del process tree (guidato dagli eventi
//! del ring buffer), il rilevamento di stati orfano/zombie richiede di
//! osservare *l'assenza* di un evento (il processo padre che termina senza
//! che il figlio venga mai riassegnato correttamente) o uno stato
//! persistente (`Z` in `/proc/<pid>/stat`). Questo modulo implementa quindi
//! una scansione periodica di `/proc`, indipendente dal flusso di eventi
//! eBPF, che incrocia lo stato osservato con il [`ProcessTree`] per capire
//! se un processo è stato "ri-parentato" a init (PID 1) rispetto al suo
//! genitore originale tracciato.

use std::sync::Arc;
use std::time::Duration;

use tracing::debug;

use super::tree::ProcessTree;

/// Stato di un processo rilevante ai fini del rilevamento orfano/zombie,
/// estratto dal campo `state` di `/proc/<pid>/stat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    Running,
    Sleeping,
    Zombie,
    Other,
}

/// Risultato di un controllo su un singolo processo tracciato.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleFinding {
    Orphaned { pid: u32, original_ppid: u32 },
    Zombie { pid: u32 },
}

/// Estrae lo stato del processo dal contenuto grezzo di `/proc/<pid>/stat`.
///
/// Isolata come funzione pura per essere testabile senza accesso reale al
/// filesystem `/proc`.
pub fn parse_proc_stat_state(stat_contents: &str) -> Option<ProcessState> {
    // Il formato di /proc/<pid>/stat è: "pid (comm) state ppid ...".
    // Il campo `comm` può contenere spazi e parentesi, quindi cerchiamo
    // l'ultima ")" per individuare correttamente l'inizio del campo state.
    let close_paren = stat_contents.rfind(')')?;
    let rest = stat_contents.get(close_paren + 2..)?;
    let state_char = rest.chars().next()?;

    Some(match state_char {
        'R' => ProcessState::Running,
        'S' | 'D' | 'I' => ProcessState::Sleeping,
        'Z' => ProcessState::Zombie,
        _ => ProcessState::Other,
    })
}

/// Estrae il PPID corrente dal contenuto di `/proc/<pid>/stat`.
pub fn parse_proc_stat_ppid(stat_contents: &str) -> Option<u32> {
    let close_paren = stat_contents.rfind(')')?;
    let rest = stat_contents.get(close_paren + 2..)?;
    // Dopo lo state character c'è uno spazio e poi il ppid.
    let mut fields = rest.split_whitespace();
    fields.next()?; // state
    fields.next()?.parse().ok()
}

/// Determina se un processo tracciato è da considerarsi orfano: il suo
/// PPID corrente (letto da `/proc`) è diverso da quello originale
/// registrato al fork, ed è stato riassegnato a init (PID 1) — il
/// comportamento standard del kernel Linux quando un processo padre
/// termina lasciando figli vivi.
pub fn is_orphaned(original_ppid: u32, current_ppid: u32) -> bool {
    current_ppid == 1 && original_ppid != 1 && original_ppid != 0
}

/// Valuta lo stato di un processo e restituisce l'elenco delle anomalie
/// rilevate (nessuna, una o entrambe). Funzione pura, separata dall'I/O
/// per essere testabile senza dipendere da `/proc` reale.
fn evaluate(
    pid: u32,
    original_ppid: u32,
    current_ppid: u32,
    state: Option<ProcessState>,
) -> Vec<LifecycleFinding> {
    let mut findings = Vec::new();

    if state == Some(ProcessState::Zombie) {
        findings.push(LifecycleFinding::Zombie { pid });
    }

    if is_orphaned(original_ppid, current_ppid) {
        findings.push(LifecycleFinding::Orphaned { pid, original_ppid });
    }

    findings
}

/// Scanner periodico che confronta lo stato reale dei processi tracciati
/// con quello atteso dal [`ProcessTree`], segnalando processi orfani o
/// zombie.
pub struct OrphanZombieScanner {
    tree: Arc<ProcessTree>,
    interval: Duration,
}

impl OrphanZombieScanner {
    pub fn new(tree: Arc<ProcessTree>, interval: Duration) -> Self {
        Self { tree, interval }
    }

    /// Esegue la scansione in loop finché il task non viene abortito
    /// dall'esterno (tramite `JoinHandle::abort` in `main.rs`).
    pub async fn run(self) {
        let mut ticker = tokio::time::interval(self.interval);
        loop {
            ticker.tick().await;
            self.scan_once();
        }
    }

    /// Singola iterazione di scansione, esposta separatamente per essere
    /// invocabile nei test senza dover attendere il timer reale.
    fn scan_once(&self) {
        for pid in self.tree.snapshot_pids() {
            let Some(original_ppid) = self.tree.resolve_ppid(pid) else {
                continue;
            };

            match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
                Ok(contents) => {
                    let state = parse_proc_stat_state(&contents);
                    let current_ppid = parse_proc_stat_ppid(&contents).unwrap_or(original_ppid);

                    for finding in evaluate(pid, original_ppid, current_ppid, state) {
                        match finding {
                            LifecycleFinding::Zombie { pid } => {
                                tracing::warn!(pid, "detected zombie process");
                            }
                            LifecycleFinding::Orphaned { pid, original_ppid } => {
                                tracing::warn!(
                                    pid,
                                    original_ppid,
                                    "detected orphaned process reparented to init"
                                );
                            }
                        }
                    }
                }
                Err(_) => {
                    // Il processo non esiste più in /proc: è terminato
                    // normalmente. Lo rimuoviamo dal tree per non
                    // continuare a scansionarlo inutilmente.
                    self.tree.remove(pid);
                    debug!(pid, "process no longer present in /proc, removed from tree");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_running_state() {
        let stat = "1234 (bash) R 1000 1234 1234 0 -1 4194304 100 0 0 0 0 0 0 0";
        assert_eq!(parse_proc_stat_state(stat), Some(ProcessState::Running));
    }

    #[test]
    fn parses_zombie_state() {
        let stat = "1234 (defunct) Z 1000 1234 1234 0 -1 4194304 100 0 0 0 0 0 0 0";
        assert_eq!(parse_proc_stat_state(stat), Some(ProcessState::Zombie));
    }

    #[test]
    fn parses_comm_with_spaces_and_parens() {
        let stat = "1234 (my (weird) proc) S 1000 1234 1234 0 -1 4194304 100";
        assert_eq!(parse_proc_stat_state(stat), Some(ProcessState::Sleeping));
    }

    #[test]
    fn parses_ppid_correctly() {
        let stat = "1234 (bash) R 1000 1234 1234 0 -1 4194304 100 0 0 0 0 0 0 0";
        assert_eq!(parse_proc_stat_ppid(stat), Some(1000));
    }

    #[test]
    fn detects_orphaned_process() {
        assert!(is_orphaned(500, 1));
        assert!(!is_orphaned(1, 1));
        assert!(!is_orphaned(500, 500));
        assert!(!is_orphaned(0, 1));
    }

    #[test]
    fn evaluate_reports_both_findings_when_applicable() {
        let findings = evaluate(42, 500, 1, Some(ProcessState::Zombie));
        assert_eq!(
            findings,
            vec![
                LifecycleFinding::Zombie { pid: 42 },
                LifecycleFinding::Orphaned {
                    pid: 42,
                    original_ppid: 500
                },
            ]
        );
    }

    #[test]
    fn evaluate_reports_nothing_for_healthy_process() {
        let findings = evaluate(42, 500, 500, Some(ProcessState::Running));
        assert!(findings.is_empty());
    }
}