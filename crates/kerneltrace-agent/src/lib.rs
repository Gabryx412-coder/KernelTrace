//! # kerneltrace-agent
//!
//! Libreria dell'agente userspace di KernelTrace. Espone i moduli
//! riutilizzabili anche dalla CLI (`kerneltrace-cli`) e dai test di
//! integrazione a livello workspace (`tests/integration`).

pub mod config;
pub mod error;
pub mod events;
pub mod loader;
pub mod telemetry;

// Moduli pianificati, aggiunti nelle parti successive dello sviluppo:
// pub mod process;
// pub mod fim;
// pub mod network;
// pub mod container;
// pub mod detection;
// pub mod anomaly;
// pub mod response;
// pub mod output;
// pub mod api;

pub use error::{AgentError, AgentResult};