//! Connection tracking: mantiene lo stato delle connessioni di rete
//! osservate, arricchendo gli eventi `connect`/`accept`/`bind`/`listen`
//! con informazioni derivate (durata della connessione, direzione,
//! correlazione con il processo che l'ha originata).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tracing::trace;

use crate::events::{Enricher, EventKind, EventPayload, NormalizedEvent};

/// Chiave univoca di una connessione di rete osservata, usata per
/// correlare eventi `connect` in ingresso con eventuali dati arricchiti
/// successivamente (es. chiusura, durata).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionKey {
    pub pid: u32,
    pub dst_addr: String,
    pub dst_port: u16,
}

/// Direzione di una connessione dal punto di vista del processo osservato.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionDirection {
    /// Il processo ha iniziato la connessione (`connect`).
    Outbound,
    /// Il processo ha accettato una connessione in ingresso (`accept`).
    Inbound,
}

/// Stato tracciato per una singola connessione attiva.
#[derive(Debug, Clone)]
pub struct ConnectionState {
    pub direction: ConnectionDirection,
    pub established_at: Instant,
    pub comm: String,
}

/// Tracker delle connessioni attive, condiviso tra la pipeline eventi (che
/// registra nuove connessioni) e i moduli di detection che ne consultano
/// lo stato (reverse shell, beaconing).
#[derive(Default)]
pub struct ConnectionTracker {
    active: RwLock<HashMap<ConnectionKey, ConnectionState>>,
}

impl ConnectionTracker {
    pub fn new() -> Self {
        Self {
            active: RwLock::new(HashMap::new()),
        }
    }

    /// Registra una nuova connessione osservata.
    pub fn record(&self, key: ConnectionKey, direction: ConnectionDirection, comm: &str) {
        self.active.write().insert(
            key,
            ConnectionState {
                direction,
                established_at: Instant::now(),
                comm: comm.to_string(),
            },
        );
    }

    /// Restituisce la durata di una connessione se ancora tracciata.
    pub fn duration(&self, key: &ConnectionKey) -> Option<Duration> {
        self.active
            .read()
            .get(key)
            .map(|state| state.established_at.elapsed())
    }

    /// Rimuove una connessione dal tracker (es. alla sua chiusura,
    /// desumibile dalla terminazione del processo che la deteneva).
    pub fn remove(&self, key: &ConnectionKey) {
        self.active.write().remove(key);
    }

    /// Numero di connessioni attualmente tracciate.
    pub fn len(&self) -> usize {
        self.active.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Istantanea delle connessioni originate da un dato PID, usata dal
    /// modulo `beaconing` per analizzare gli intervalli temporali tra
    /// connessioni successive verso la stessa destinazione.
    pub fn connections_for_pid(&self, pid: u32) -> Vec<ConnectionKey> {
        self.active
            .read()
            .keys()
            .filter(|k| k.pid == pid)
            .cloned()
            .collect()
    }
}

/// Arricchitore che alimenta il [`ConnectionTracker`] a partire dagli
/// eventi di rete normalizzati.
pub struct ConnectionTrackerEnricher {
    tracker: Arc<ConnectionTracker>,
}

impl ConnectionTrackerEnricher {
    pub fn new(tracker: Arc<ConnectionTracker>) -> Self {
        Self { tracker }
    }
}

impl Enricher for ConnectionTrackerEnricher {
    fn enrich(&self, event: &mut NormalizedEvent) {
        let EventPayload::Network {
            dst_addr, dst_port, ..
        } = &event.payload
        else {
            return;
        };

        let key = ConnectionKey {
            pid: event.process.pid,
            dst_addr: dst_addr.clone(),
            dst_port: *dst_port,
        };

        let direction = match event.event_kind {
            EventKind::Connect => ConnectionDirection::Outbound,
            EventKind::AcceptBindListen => ConnectionDirection::Inbound,
            _ => return,
        };

        self.tracker.record(key, direction, &event.process.comm);
        trace!(pid = event.process.pid, dst_addr, dst_port, "connection tracked");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_and_retrieves_connection_duration() {
        let tracker = ConnectionTracker::new();
        let key = ConnectionKey {
            pid: 100,
            dst_addr: "10.0.0.5".to_string(),
            dst_port: 4444,
        };

        tracker.record(key.clone(), ConnectionDirection::Outbound, "nc");
        let duration = tracker.duration(&key);
        assert!(duration.is_some());
    }

    #[test]
    fn remove_drops_connection() {
        let tracker = ConnectionTracker::new();
        let key = ConnectionKey {
            pid: 200,
            dst_addr: "10.0.0.6".to_string(),
            dst_port: 443,
        };

        tracker.record(key.clone(), ConnectionDirection::Outbound, "curl");
        assert_eq!(tracker.len(), 1);

        tracker.remove(&key);
        assert!(tracker.is_empty());
    }

    #[test]
    fn connections_for_pid_filters_correctly() {
        let tracker = ConnectionTracker::new();
        tracker.record(
            ConnectionKey {
                pid: 1,
                dst_addr: "1.1.1.1".to_string(),
                dst_port: 80,
            },
            ConnectionDirection::Outbound,
            "curl",
        );
        tracker.record(
            ConnectionKey {
                pid: 2,
                dst_addr: "2.2.2.2".to_string(),
                dst_port: 80,
            },
            ConnectionDirection::Outbound,
            "wget",
        );

        let connections = tracker.connections_for_pid(1);
        assert_eq!(connections.len(), 1);
        assert_eq!(connections[0].pid, 1);
    }
}