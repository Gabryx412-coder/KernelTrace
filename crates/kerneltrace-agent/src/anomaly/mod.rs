//! Predisposizione architetturale per un futuro motore di anomaly
//! detection basato su machine learning (vedi ROADMAP.md). Nessuna
//! implementazione concreta di ML è presente in questa fase; questo
//! modulo espone solo l'interfaccia (`AnomalyEngine`) e un'implementazione
//! no-op di default.

pub mod engine_trait;

pub use engine_trait::{AnomalyEngine, AnomalyScore, NoopAnomalyEngine};