//! Predisposizione architetturale per l'estensibilità tramite plugin di
//! terze parti (vedi ROADMAP.md per il caricamento dinamico futuro).

pub mod plugin_trait;

pub use plugin_trait::{Plugin, PluginMetadata};