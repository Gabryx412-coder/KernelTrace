//! Caricamento e validazione del file di configurazione YAML.

use std::path::{Path, PathBuf};

use crate::error::{AgentError, AgentResult};

use super::schema::Config;

/// Carica la configurazione da un percorso su disco, applicando i valori
/// di default per ogni campo omesso e validando i vincoli semantici che
/// `serde` da solo non può esprimere (es. path esistenti, valori coerenti
/// tra loro).
pub fn load_config(path: impl AsRef<Path>) -> AgentResult<Config> {
    let path = path.as_ref();
    let raw = std::fs::read_to_string(path).map_err(AgentError::Io)?;
    let config: Config =
        serde_yaml::from_str(&raw).map_err(|source| AgentError::ConfigLoad {
            path: path.to_path_buf(),
            source,
        })?;

    validate(&config)?;
    Ok(config)
}

/// Applica le regole di validazione semantica sulla configurazione caricata.
fn validate(config: &Config) -> AgentResult<()> {
    if config.agent.pipeline_capacity == 0 {
        return Err(AgentError::ConfigValidation(
            "agent.pipeline_capacity must be greater than zero".to_string(),
        ));
    }

    for dir in &config.rules.directories {
        if !dir.exists() {
            return Err(AgentError::ConfigValidation(format!(
                "rules directory does not exist: {}",
                dir.display()
            )));
        }
    }

    if config
        .output
        .sinks
        .iter()
        .any(|sink| matches!(sink, super::schema::OutputSinkKind::File | super::schema::OutputSinkKind::Json))
        && config.output.file_path.is_none()
    {
        return Err(AgentError::ConfigValidation(
            "output.file_path must be set when a 'file' or 'json' sink is enabled".to_string(),
        ));
    }

    Ok(())
}

/// Restituisce il percorso di configurazione di default cercato dalla CLI
/// quando `--config` non è specificato esplicitamente.
pub fn default_config_path() -> PathBuf {
    PathBuf::from("/etc/kerneltrace/kerneltrace.yaml")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn loads_minimal_valid_config() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "agent:\n  pipeline_capacity: 1024\n").unwrap();

        let config = load_config(file.path()).expect("should load");
        assert_eq!(config.agent.pipeline_capacity, 1024);
    }

    #[test]
    fn rejects_zero_pipeline_capacity() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "agent:\n  pipeline_capacity: 0\n").unwrap();

        let result = load_config(file.path());
        assert!(matches!(result, Err(AgentError::ConfigValidation(_))));
    }

    #[test]
    fn rejects_unknown_fields() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "agent:\n  totally_unknown_field: true\n").unwrap();

        let result = load_config(file.path());
        assert!(result.is_err());
    }

    #[test]
    fn missing_file_returns_io_error() {
        let result = load_config("/nonexistent/path/kerneltrace.yaml");
        assert!(matches!(result, Err(AgentError::Io(_))));
    }
}