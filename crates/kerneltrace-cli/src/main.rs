//! Entry point della CLI `kerneltrace-cli`.

mod commands;
mod output_format;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use output_format::OutputFormat;

/// KernelTrace: interfaccia a riga di comando per la gestione dell'agente HIDS.
#[derive(Debug, Parser)]
#[command(name = "kerneltrace-cli", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: TopLevelCommand,
}

#[derive(Debug, Subcommand)]
enum TopLevelCommand {
    /// Avvia l'agente KernelTrace.
    Start {
        /// Percorso del file di configurazione YAML.
        #[arg(long, short)]
        config: Option<PathBuf>,
        /// Avvia l'agente in background invece che in foreground.
        #[arg(long)]
        detach: bool,
    },
    /// Mostra lo stato corrente dell'agente (in esecuzione o meno).
    Status {
        #[arg(long, short)]
        config: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
        format: OutputFormat,
    },
    /// Gestione e ispezione delle regole di detection.
    Rules {
        #[command(subcommand)]
        command: commands::rules::RulesCommand,
    },
    /// Gestione e ispezione della configurazione.
    Config {
        #[command(subcommand)]
        command: commands::config::ConfigCommand,
    },
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("info"))
        .init();

    let cli = Cli::parse();

    match cli.command {
        TopLevelCommand::Start { config, detach } => commands::start::run(config, detach),
        TopLevelCommand::Status { config, format } => commands::status::run(config, format),
        TopLevelCommand::Rules { command } => commands::rules::run(command),
        TopLevelCommand::Config { command } => commands::config::run(command),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        // `debug_assert` di clap verifica che la definizione degli
        // argomenti (nomi duplicati, conflitti, ecc.) sia internamente
        // consistente, individuando errori di configurazione della CLI a
        // livello di test piuttosto che a runtime.
        Cli::command().debug_assert();
    }
}