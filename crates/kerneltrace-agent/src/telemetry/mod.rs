//! Setup della telemetria (logging strutturato) dell'agente.

mod tracing_setup;

pub use tracing_setup::{init_tracing, TelemetryGuard};