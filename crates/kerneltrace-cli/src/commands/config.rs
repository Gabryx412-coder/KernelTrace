//! Comando `kerneltrace-cli config`: ispezione e validazione della
//! configurazione YAML, senza richiedere privilegi eBPF.

use std::path::PathBuf;

use clap::Subcommand;
use kerneltrace_agent::config::{self, Config};

use crate::output_format::{print_json, OutputFormat};

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Mostra la configurazione effettiva, caricando il file indicato (o
    /// quello di default) e applicando i valori di default per i campi omessi.
    Show {
        #[arg(long, short)]
        config: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
        format: OutputFormat,
    },
    /// Stampa una configurazione di default completa, utile come punto di
    /// partenza per creare un nuovo file `kerneltrace.yaml`.
    PrintDefault {
        #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
        format: OutputFormat,
    },
    /// Valida un file di configurazione senza avviare l'agente né caricare
    /// programmi eBPF.
    Validate {
        #[arg(long, short)]
        config: PathBuf,
    },
}

pub fn run(command: ConfigCommand) -> anyhow::Result<()> {
    match command {
        ConfigCommand::Show { config: path, format } => run_show(path, format),
        ConfigCommand::PrintDefault { format } => run_print_default(format),
        ConfigCommand::Validate { config: path } => run_validate(path),
    }
}

fn run_show(path: Option<PathBuf>, format: OutputFormat) -> anyhow::Result<()> {
    let path = path.unwrap_or_else(config::default_config_path);
    let cfg = config::load_config(&path)?;
    print_config(&cfg, format)
}

fn run_print_default(format: OutputFormat) -> anyhow::Result<()> {
    let cfg = config::default_config();
    print_config(&cfg, format)
}

fn run_validate(path: PathBuf) -> anyhow::Result<()> {
    match config::load_config(&path) {
        Ok(_) => {
            println!("Configuration at {} is valid.", path.display());
            Ok(())
        }
        Err(err) => {
            eprintln!("Configuration at {} is INVALID: {err}", path.display());
            std::process::exit(1);
        }
    }
}

fn print_config(cfg: &Config, format: OutputFormat) -> anyhow::Result<()> {
    match format {
        OutputFormat::Json => print_json(cfg),
        OutputFormat::Table => {
            let yaml = serde_yaml::to_string(cfg)?;
            println!("{yaml}");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn print_default_config_succeeds_in_both_formats() {
        assert!(run_print_default(OutputFormat::Table).is_ok());
        assert!(run_print_default(OutputFormat::Json).is_ok());
    }

    #[test]
    fn validate_nonexistent_config_exits_nonzero() {
        // Non possiamo testare std::process::exit direttamente in-process
        // senza terminare il test runner; verifichiamo invece che
        // load_config restituisca un errore per un path inesistente,
        // il comportamento sottostante di run_validate.
        let result = config::load_config("/nonexistent/kerneltrace.yaml");
        assert!(result.is_err());
    }
}