//! Modulo di configurazione: schema YAML, caricamento e valori di default.

mod defaults;
mod loader;
mod schema;

pub use defaults::default_config;
pub use loader::{default_config_path, load_config};
pub use schema::{
    AgentSettings, Config, ContainerSettings, LogFormat, LoggingSettings, MonitoringSettings,
    OutputSettings, OutputSinkKind, RulesSettings,
};