//! Formattazione dell'output della CLI, condivisa tra i vari comandi.

use clap::ValueEnum;
use serde::Serialize;

/// Formato di output selezionabile dall'utente tramite `--format`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Testo leggibile, pensato per la lettura interattiva da terminale.
    Table,
    /// JSON, pensato per l'uso in script o pipeline di automazione.
    Json,
}

impl Default for OutputFormat {
    fn default() -> Self {
        OutputFormat::Table
    }
}

/// Serializza un valore secondo il formato richiesto e lo stampa su
/// stdout. Per il formato `Table`, il chiamante deve aver già preparato
/// una rappresentazione testuale tramite `Display`/formattazione manuale;
/// questa funzione gestisce solo il caso `Json` in modo generico.
pub fn print_json<T: Serialize>(value: &T) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(value)?;
    println!("{json}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize)]
    struct Sample {
        name: String,
        count: u32,
    }

    #[test]
    fn print_json_serializes_without_error() {
        let sample = Sample {
            name: "test".to_string(),
            count: 3,
        };
        assert!(print_json(&sample).is_ok());
    }

    #[test]
    fn default_format_is_table() {
        assert_eq!(OutputFormat::default(), OutputFormat::Table);
    }
}