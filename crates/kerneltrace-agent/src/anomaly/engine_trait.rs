//! Trait per un futuro motore di anomaly detection basato su machine
//! learning, predisposto architetturalmente ma non implementato in questa
//! fase del progetto (vedi ROADMAP.md).
//!
//! L'idea di design è che un modello ML (es. un autoencoder addestrato
//! sulla distribuzione "normale" di eventi di un host, o un classificatore
//! sequenziale sulla process tree) possa essere collegato come ulteriore
//! stadio della pipeline, esattamente come gli `Enricher` già esistenti,
//! senza richiedere modifiche al resto dell'architettura: riceve un
//! evento già arricchito (container, process tree, tag del rules engine)
//! e restituisce un punteggio di anomalia, che il chiamante può tradurre
//! in un ulteriore tag (es. `anomaly_score:0.92`) o in un trigger per il
//! modulo `response`.

use serde::{Deserialize, Serialize};

use crate::events::NormalizedEvent;

/// Punteggio di anomalia normalizzato tra 0.0 (comportamento perfettamente
/// atteso) e 1.0 (massima anomalia), restituito da un `AnomalyEngine`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct AnomalyScore(f64);

impl AnomalyScore {
    /// Costruisce un punteggio, troncando (clamping) a `[0.0, 1.0]` per
    /// garantire che implementazioni future di `AnomalyEngine` non possano
    /// produrre valori fuori range che romperebbero i confronti a valle
    /// (es. soglie configurate dall'utente).
    pub fn new(value: f64) -> Self {
        Self(value.clamp(0.0, 1.0))
    }

    pub fn value(&self) -> f64 {
        self.0
    }

    /// Punteggio minimo, rappresentativo di "nessuna anomalia rilevata".
    pub fn none() -> Self {
        Self(0.0)
    }

    /// Determina se il punteggio supera una soglia data, con confronto
    /// inclusivo (`>=`) per evitare ambiguità ai valori limite esatti.
    pub fn exceeds(&self, threshold: f64) -> bool {
        self.0 >= threshold
    }
}

impl Default for AnomalyScore {
    fn default() -> Self {
        Self::none()
    }
}

/// Interfaccia comune per un motore di anomaly detection, applicabile a
/// un singolo evento normalizzato. Implementazioni concrete (statistiche,
/// ML) vivranno in questo stesso modulo o in crate esterni che
/// dipendono da `kerneltrace-agent` come libreria.
pub trait AnomalyEngine: Send + Sync {
    /// Nome del motore, usato nei log e nei tag applicati agli eventi.
    fn name(&self) -> &'static str;

    /// Calcola il punteggio di anomalia per un evento. Non deve avere
    /// side-effect osservabili dall'esterno oltre al proprio stato interno
    /// (es. aggiornamento di statistiche incrementali), per restare
    /// componibile con gli altri stadi della pipeline.
    fn score(&self, event: &NormalizedEvent) -> AnomalyScore;
}

/// Implementazione no-op, usata come motore di default finché non viene
/// configurato un motore concreto. Restituisce sempre il punteggio
/// minimo, equivalente a disabilitare l'anomaly detection senza dover
/// introdurre rami condizionali nel resto della pipeline.
pub struct NoopAnomalyEngine;

impl AnomalyEngine for NoopAnomalyEngine {
    fn name(&self) -> &'static str {
        "noop"
    }

    fn score(&self, _event: &NormalizedEvent) -> AnomalyScore {
        AnomalyScore::none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_clamps_values_above_one() {
        let score = AnomalyScore::new(1.5);
        assert_eq!(score.value(), 1.0);
    }

    #[test]
    fn score_clamps_negative_values() {
        let score = AnomalyScore::new(-0.5);
        assert_eq!(score.value(), 0.0);
    }

    #[test]
    fn exceeds_is_inclusive_at_threshold() {
        let score = AnomalyScore::new(0.8);
        assert!(score.exceeds(0.8));
        assert!(!score.exceeds(0.81));
    }

    #[test]
    fn noop_engine_always_returns_zero() {
        use crate::events::{EventKind, EventPayload, ProcessContext};
        use chrono::Utc;
        use uuid::Uuid;

        let event = NormalizedEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_kind: EventKind::Exec,
            process: ProcessContext {
                pid: 1,
                tgid: 1,
                ppid: 0,
                uid: 0,
                gid: 0,
                comm: "init".to_string(),
                cgroup_id: 0,
                parent_comm: None,
            },
            payload: EventPayload::Exec {
                filename: "/sbin/init".to_string(),
                args: vec![],
            },
            container: None,
            tags: vec![],
        };

        let engine = NoopAnomalyEngine;
        assert_eq!(engine.score(&event), AnomalyScore::none());
    }
}