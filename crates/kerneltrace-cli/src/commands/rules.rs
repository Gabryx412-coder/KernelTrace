//! Comando `kerneltrace-cli rules`: ispezione e validazione delle regole
//! di detection YAML, senza richiedere l'avvio dell'agente.

use std::path::PathBuf;

use clap::Subcommand;
use kerneltrace_agent::config;
use kerneltrace_agent::detection::{load_all_rules, Rule};
use serde::Serialize;

use crate::output_format::{print_json, OutputFormat};

#[derive(Debug, Subcommand)]
pub enum RulesCommand {
    /// Elenca tutte le regole caricate dalle directory configurate.
    List {
        #[arg(long, short)]
        config: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
        format: OutputFormat,
    },
    /// Valida la sintassi di tutte le regole, segnalando eventuali errori
    /// di parsing senza avviare l'agente.
    Validate {
        #[arg(long, short)]
        config: Option<PathBuf>,
    },
}

#[derive(Debug, Serialize)]
struct RuleSummary {
    id: String,
    name: String,
    severity: String,
    enabled: bool,
}

impl From<&Rule> for RuleSummary {
    fn from(rule: &Rule) -> Self {
        Self {
            id: rule.id.clone(),
            name: rule.name.clone(),
            severity: format!("{:?}", rule.severity).to_lowercase(),
            enabled: rule.enabled,
        }
    }
}

pub fn run(command: RulesCommand) -> anyhow::Result<()> {
    match command {
        RulesCommand::List { config: path, format } => run_list(path, format),
        RulesCommand::Validate { config: path } => run_validate(path),
    }
}

fn load_rules_from_config(path: Option<PathBuf>) -> anyhow::Result<Vec<Rule>> {
    let path = path.unwrap_or_else(config::default_config_path);
    let cfg = config::load_config(&path)?;
    let rules = load_all_rules(&cfg.rules.directories, cfg.rules.strict_parsing)?;
    Ok(rules)
}

fn run_list(path: Option<PathBuf>, format: OutputFormat) -> anyhow::Result<()> {
    let rules = load_rules_from_config(path)?;
    let summaries: Vec<RuleSummary> = rules.iter().map(RuleSummary::from).collect();

    match format {
        OutputFormat::Json => print_json(&summaries),
        OutputFormat::Table => {
            println!("{:<40} {:<45} {:<10} {:<8}", "ID", "NAME", "SEVERITY", "ENABLED");
            for summary in &summaries {
                println!(
                    "{:<40} {:<45} {:<10} {:<8}",
                    summary.id, summary.name, summary.severity, summary.enabled
                );
            }
            println!("\n{} rule(s) loaded.", summaries.len());
            Ok(())
        }
    }
}

fn run_validate(path: Option<PathBuf>) -> anyhow::Result<()> {
    match load_rules_from_config(path) {
        Ok(rules) => {
            println!("All {} rule(s) parsed successfully.", rules.len());
            Ok(())
        }
        Err(err) => {
            eprintln!("Rule validation FAILED: {err}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_summary_lowercases_severity() {
        use kerneltrace_agent::detection::{MatchSpec, Operator, FieldCondition, Rule, Severity};

        let rule = Rule {
            id: "test".to_string(),
            name: "Test".to_string(),
            description: String::new(),
            severity: Severity::Critical,
            match_spec: MatchSpec::Simple {
                conditions: vec![FieldCondition {
                    field: "process.comm".to_string(),
                    operator: Operator::Equals,
                    value: "bash".to_string(),
                }],
            },
            tags: vec![],
            enabled: true,
        };

        let summary = RuleSummary::from(&rule);
        assert_eq!(summary.severity, "critical");
        assert!(summary.enabled);
    }
}