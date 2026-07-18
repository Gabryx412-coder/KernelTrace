//! # kerneltrace-agent
//!
//! Libreria dell'agente userspace di KernelTrace.

pub mod config;
pub mod error;
pub mod events;
pub mod fim;
pub mod loader;
pub mod network;
pub mod process;
pub mod telemetry;

// Moduli pianificati, aggiunti nelle parti successive dello sviluppo:
// pub mod container;
// pub mod detection;
// pub mod anomaly;
// pub mod response;
// pub mod output;
// pub mod api;

pub use error::{AgentError, AgentResult};