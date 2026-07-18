//! Rilevamento di privilege escalation basato sull'osservazione dei
//! cambi di UID nel tempo per un dato processo.
//!
//! Questa prima implementazione osserva l'UID riportato in ogni evento
//! (`ProcessContext::uid`) e segnala una transizione sospetta quando un
//! processo che non era root lo diventa. Una volta disponibile la probe
//! dedicata su `setuid`/`setgid` (Parte 6), l'evento `PrivilegeChange`
//! fornirà UID vecchio/nuovo espliciti; questo detector continuerà comunque
//! a funzionare come rete di sicurezza aggiuntiva, dato che osserva il
//! comportamento effettivo del processo indipendentemente dalla syscall
//! specifica che ha causato il cambio.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use tracing::warn;

use crate::events::{Enricher, NormalizedEvent};

/// Tag applicato agli eventi in cui è stata rilevata un'escalation di
/// privilegi, consultabile dal rules engine (Parte 10) e dagli output sink.
pub const PRIVILEGE_ESCALATION_TAG: &str = "privilege_escalation";

/// Tiene traccia dell'ultimo UID osservato per ciascun PID.
#[derive(Default)]
struct UidTracker {
    last_seen_uid: HashMap<u32, u32>,
}

impl UidTracker {
    /// Registra l'UID osservato per un PID e restituisce `true` se questa
    /// osservazione rappresenta un'escalation a root (UID 0) rispetto a un
    /// UID non privilegiato osservato in precedenza per lo stesso PID.
    fn observe(&mut self, pid: u32, uid: u32) -> bool {
        let escalated = match self.last_seen_uid.get(&pid) {
            Some(&previous_uid) => previous_uid != 0 && uid == 0,
            None => false,
        };
        self.last_seen_uid.insert(pid, uid);
        escalated
    }

    fn forget(&mut self, pid: u32) {
        self.last_seen_uid.remove(&pid);
    }
}

/// Arricchitore che rileva escalation di privilegi osservando i cambi di
/// UID nel tempo per ciascun processo tracciato.
pub struct PrivilegeEscalationEnricher {
    tracker: Arc<Mutex<UidTracker>>,
}

impl PrivilegeEscalationEnricher {
    pub fn new() -> Self {
        Self {
            tracker: Arc::new(Mutex::new(UidTracker::default())),
        }
    }

    /// Rimuove lo stato tracciato per un PID terminato. Può essere
    /// collegato in futuro allo scanner di `lifecycle` quando un processo
    /// scompare da `/proc`, per evitare crescita illimitata della mappa
    /// interna su host con alto tasso di creazione processi.
    pub fn forget(&self, pid: u32) {
        self.tracker.lock().forget(pid);
    }
}

impl Default for PrivilegeEscalationEnricher {
    fn default() -> Self {
        Self::new()
    }
}

impl Enricher for PrivilegeEscalationEnricher {
    fn enrich(&self, event: &mut NormalizedEvent) {
        let escalated = self
            .tracker
            .lock()
            .observe(event.process.pid, event.process.uid);

        if escalated {
            warn!(
                pid = event.process.pid,
                comm = %event.process.comm,
                "detected privilege escalation to root"
            );
            event.tags.push(PRIVILEGE_ESCALATION_TAG.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_escalation_from_non_root_to_root() {
        let mut tracker = UidTracker::default();
        assert!(!tracker.observe(100, 1000)); // primo avvistamento, nessuna escalation
        assert!(tracker.observe(100, 0)); // stesso pid, ora root: escalation
    }

    #[test]
    fn does_not_flag_process_that_starts_as_root() {
        let mut tracker = UidTracker::default();
        assert!(!tracker.observe(200, 0));
    }

    #[test]
    fn does_not_flag_repeated_root_observations() {
        let mut tracker = UidTracker::default();
        tracker.observe(300, 0); // primo avvistamento, già come root
        assert!(!tracker.observe(300, 0)); // già root, nessuna nuova escalation
    }

    #[test]
    fn forget_clears_tracked_state() {
        let mut tracker = UidTracker::default();
        tracker.observe(400, 1000);
        tracker.forget(400);
        // Dopo il forget, un nuovo avvistamento a UID 0 non è considerato
        // un'escalation perché non c'è più storico per il pid.
        assert!(!tracker.observe(400, 0));
    }
}