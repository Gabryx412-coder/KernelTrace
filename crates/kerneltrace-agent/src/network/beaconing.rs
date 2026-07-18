//! Rilevamento di beaconing: connessioni ripetute a intervalli regolari
//! verso la stessa destinazione, pattern tipico di comunicazione C2
//! (command & control) malevola.
//!
//! L'implementazione mantiene, per ciascuna combinazione (pid,
//! destinazione), una cronologia degli istanti di connessione. Quando la
//! varianza tra gli intervalli osservati è sufficientemente bassa (jitter
//! ridotto) su un numero minimo di campioni, l'evento viene taggato come
//! sospetto beaconing.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;

use crate::events::{Enricher, EventKind, EventPayload, NormalizedEvent};

pub const TAG_SUSPECTED_BEACONING: &str = "suspected_beaconing";

/// Numero minimo di connessioni osservate prima di poter valutare la
/// regolarità degli intervalli (troppo pochi campioni producono falsi
/// positivi/negativi inaffidabili).
const MIN_SAMPLES: usize = 5;

/// Numero massimo di timestamp mantenuti in cronologia per ciascuna
/// destinazione, per limitare la crescita di memoria su host con traffico
/// intenso verso poche destinazioni (es. connessioni legittime e frequenti
/// a un load balancer interno).
const MAX_HISTORY: usize = 20;

/// Soglia di coefficiente di variazione (deviazione standard / media)
/// sotto la quale gli intervalli sono considerati "troppo regolari" per
/// essere traffico umano/applicativo naturale.
const REGULARITY_THRESHOLD: f64 = 0.15;

#[derive(Debug, Clone, Default)]
struct DestinationHistory {
    timestamps: Vec<Instant>,
}

impl DestinationHistory {
    fn push(&mut self, when: Instant) {
        self.timestamps.push(when);
        if self.timestamps.len() > MAX_HISTORY {
            self.timestamps.remove(0);
        }
    }

    fn intervals(&self) -> Vec<Duration> {
        self.timestamps
            .windows(2)
            .map(|pair| pair[1].duration_since(pair[0]))
            .collect()
    }
}

/// Calcola il coefficiente di variazione (CV) di una serie di durate.
/// Un CV basso indica intervalli molto regolari tra loro (sospetto),
/// mentre traffico applicativo/umano naturale tende ad avere CV più alto.
///
/// Funzione pura, testabile indipendentemente dal tracker con stato.
pub fn coefficient_of_variation(intervals: &[Duration]) -> Option<f64> {
    if intervals.is_empty() {
        return None;
    }

    let secs: Vec<f64> = intervals.iter().map(|d| d.as_secs_f64()).collect();
    let mean = secs.iter().sum::<f64>() / secs.len() as f64;

    if mean == 0.0 {
        return None;
    }

    let variance = secs.iter().map(|s| (s - mean).powi(2)).sum::<f64>() / secs.len() as f64;
    let std_dev = variance.sqrt();

    Some(std_dev / mean)
}

/// Determina se una serie di intervalli rappresenta un pattern di
/// beaconing sospetto: abbastanza campioni e coefficiente di variazione
/// sotto soglia.
pub fn is_beaconing_pattern(intervals: &[Duration]) -> bool {
    if intervals.len() + 1 < MIN_SAMPLES {
        return false;
    }

    match coefficient_of_variation(intervals) {
        Some(cv) => cv < REGULARITY_THRESHOLD,
        None => false,
    }
}

/// Tracker della cronologia delle connessioni per destinazione, usato dal
/// [`BeaconingDetector`].
#[derive(Default)]
pub struct BeaconingTracker {
    history: RwLock<HashMap<(u32, String, u16), DestinationHistory>>,
}

impl BeaconingTracker {
    pub fn new() -> Self {
        Self {
            history: RwLock::new(HashMap::new()),
        }
    }

    /// Registra una nuova connessione e restituisce `true` se il pattern
    /// risultante è sospetto di beaconing.
    pub fn observe(&self, pid: u32, dst_addr: &str, dst_port: u16) -> bool {
        let key = (pid, dst_addr.to_string(), dst_port);
        let mut history = self.history.write();
        let entry = history.entry(key).or_default();
        entry.push(Instant::now());

        is_beaconing_pattern(&entry.intervals())
    }
}

/// Arricchitore che collega il [`BeaconingTracker`] agli eventi `connect`
/// normalizzati.
pub struct BeaconingDetector {
    tracker: Arc<BeaconingTracker>,
}

impl BeaconingDetector {
    pub fn new(tracker: Arc<BeaconingTracker>) -> Self {
        Self { tracker }
    }
}

impl Enricher for BeaconingDetector {
    fn enrich(&self, event: &mut NormalizedEvent) {
        if event.event_kind != EventKind::Connect {
            return;
        }

        let EventPayload::Network {
            dst_addr, dst_port, ..
        } = &event.payload
        else {
            return;
        };

        let suspicious = self
            .tracker
            .observe(event.process.pid, dst_addr, *dst_port);

        if suspicious {
            event.tags.push(TAG_SUSPECTED_BEACONING.to_string());
            tracing::warn!(
                pid = event.process.pid,
                dst_addr,
                dst_port,
                "suspected beaconing pattern detected"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_regular_intervals_as_beaconing() {
        let intervals = vec![
            Duration::from_secs(60),
            Duration::from_secs(61),
            Duration::from_secs(59),
            Duration::from_secs(60),
            Duration::from_secs(60),
        ];
        assert!(is_beaconing_pattern(&intervals));
    }

    #[test]
    fn does_not_flag_irregular_intervals() {
        let intervals = vec![
            Duration::from_secs(5),
            Duration::from_secs(120),
            Duration::from_secs(3),
            Duration::from_secs(200),
            Duration::from_secs(1),
        ];
        assert!(!is_beaconing_pattern(&intervals));
    }

    #[test]
    fn does_not_flag_insufficient_samples() {
        let intervals = vec![Duration::from_secs(60), Duration::from_secs(60)];
        assert!(!is_beaconing_pattern(&intervals));
    }

    #[test]
    fn coefficient_of_variation_is_zero_for_identical_intervals() {
        let intervals = vec![Duration::from_secs(30); 5];
        let cv = coefficient_of_variation(&intervals).unwrap();
        assert!(cv < 0.001);
    }

    #[test]
    fn tracker_flags_after_enough_regular_samples() {
        let tracker = BeaconingTracker::new();
        // I primi campioni non sono sufficienti per una valutazione.
        for _ in 0..3 {
            let flagged = tracker.observe(1, "10.0.0.1", 443);
            assert!(!flagged);
        }
    }
}