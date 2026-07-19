//! # kerneltrace-agent
//!
//! Libreria dell'agente userspace di KernelTrace.

pub mod anomaly;
pub mod api;
pub mod config;
pub mod container;
pub mod detection;
pub mod error;
pub mod events;
pub mod fim;
pub mod loader;
pub mod network;
pub mod output;
pub mod process;
pub mod response;
pub mod telemetry;

pub use error::{AgentError, AgentResult};