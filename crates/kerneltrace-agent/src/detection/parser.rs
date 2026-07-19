//! Caricamento delle regole YAML da una o più directory.

use std::path::{Path, PathBuf};

use tracing::{info, warn};

use crate::error::{AgentError, AgentResult};

use super::rule::Rule;

/// Carica tutte le regole `.yaml`/`.yml` da una directory (non
/// ricorsivamente: le sotto-directory vanno elencate esplicitamente in
/// `rules.directories` se necessario, per un comportamento prevedibile).
///
/// Se `strict` è `true`, un errore di parsing su un singolo file
/// interrompe il caricamento con un errore; se `false`, il file viene
/// saltato con un warning e il caricamento prosegue con gli altri.
pub fn load_rules_from_directory(dir: &Path, strict: bool) -> AgentResult<Vec<Rule>> {
    let mut rules = Vec::new();

    let entries = std::fs::read_dir(dir).map_err(AgentError::Io)?;

    for entry in entries {
        let entry = entry.map_err(AgentError::Io)?;
        let path = entry.path();

        let is_yaml = path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext == "yaml" || ext == "yml")
            .unwrap_or(false);

        if !is_yaml {
            continue;
        }

        match load_rule_file(&path) {
            Ok(rule) => {
                info!(rule_id = %rule.id, path = %path.display(), "loaded detection rule");
                rules.push(rule);
            }
            Err(err) => {
                if strict {
                    return Err(err);
                }
                warn!(path = %path.display(), error = %err, "failed to parse rule file, skipping");
            }
        }
    }

    Ok(rules)
}

/// Carica e valida una singola regola da un file YAML.
pub fn load_rule_file(path: &Path) -> AgentResult<Rule> {
    let contents = std::fs::read_to_string(path).map_err(AgentError::Io)?;
    let rule: Rule = serde_yaml::from_str(&contents).map_err(|err| AgentError::RuleParse {
        path: path.to_path_buf(),
        message: err.to_string(),
    })?;

    validate_rule(&rule, path)?;
    Ok(rule)
}

fn validate_rule(rule: &Rule, path: &Path) -> AgentResult<()> {
    if rule.id.trim().is_empty() {
        return Err(AgentError::RuleParse {
            path: path.to_path_buf(),
            message: "rule id must not be empty".to_string(),
        });
    }

    match &rule.match_spec {
        super::rule::MatchSpec::Simple { conditions } if conditions.is_empty() => {
            Err(AgentError::RuleParse {
                path: path.to_path_buf(),
                message: "simple match spec must have at least one condition".to_string(),
            })
        }
        super::rule::MatchSpec::Sequence {
            first,
            then,
            within_seconds,
            ..
        } if first.is_empty() || then.is_empty() || *within_seconds == 0 => {
            Err(AgentError::RuleParse {
                path: path.to_path_buf(),
                message:
                    "sequence match spec requires non-empty 'first'/'then' and within_seconds > 0"
                        .to_string(),
            })
        }
        _ => Ok(()),
    }
}

/// Carica le regole da tutte le directory configurate, combinandole in un
/// unico vettore. Le directory inesistenti sono già state respinte in
/// fase di validazione della configurazione (`config::loader`), quindi qui
/// ci si aspetta che tutte esistano.
pub fn load_all_rules(directories: &[PathBuf], strict: bool) -> AgentResult<Vec<Rule>> {
    let mut all_rules = Vec::new();
    for dir in directories {
        let mut rules = load_rules_from_directory(dir, strict)?;
        all_rules.append(&mut rules);
    }
    Ok(all_rules)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn loads_valid_rule_file() {
        let dir = tempfile::tempdir().unwrap();
        let rule_path = dir.path().join("test.yaml");
        let mut file = std::fs::File::create(&rule_path).unwrap();
        writeln!(
            file,
            r#"
id: test-rule
name: Test
severity: low
match:
  kind: simple
  conditions:
    - field: process.comm
      operator: equals
      value: bash
"#
        )
        .unwrap();

        let rule = load_rule_file(&rule_path).expect("should load");
        assert_eq!(rule.id, "test-rule");
    }

    #[test]
    fn rejects_rule_with_empty_conditions() {
        let dir = tempfile::tempdir().unwrap();
        let rule_path = dir.path().join("bad.yaml");
        let mut file = std::fs::File::create(&rule_path).unwrap();
        writeln!(
            file,
            r#"
id: bad-rule
name: Bad
severity: low
match:
  kind: simple
  conditions: []
"#
        )
        .unwrap();

        let result = load_rule_file(&rule_path);
        assert!(matches!(result, Err(AgentError::RuleParse { .. })));
    }

    #[test]
    fn directory_loader_skips_invalid_files_in_non_strict_mode() {
        let dir = tempfile::tempdir().unwrap();

        let mut good = std::fs::File::create(dir.path().join("good.yaml")).unwrap();
        writeln!(
            good,
            r#"
id: good-rule
name: Good
severity: low
match:
  kind: simple
  conditions:
    - field: process.comm
      operator: equals
      value: bash
"#
        )
        .unwrap();

        let mut bad = std::fs::File::create(dir.path().join("bad.yaml")).unwrap();
        writeln!(bad, "not: [valid, yaml: structure for a rule").unwrap();

        let rules = load_rules_from_directory(dir.path(), false).expect("should not fail");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "good-rule");
    }

    #[test]
    fn directory_loader_fails_fast_in_strict_mode() {
        let dir = tempfile::tempdir().unwrap();
        let mut bad = std::fs::File::create(dir.path().join("bad.yaml")).unwrap();
        writeln!(bad, "id: \nname: Bad\nseverity: low\nmatch:\n  kind: simple\n  conditions: []").unwrap();

        let result = load_rules_from_directory(dir.path(), true);
        assert!(result.is_err());
    }

    #[test]
    fn ignores_non_yaml_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("README.md"), "not a rule").unwrap();

        let rules = load_rules_from_directory(dir.path(), true).expect("should succeed");
        assert!(rules.is_empty());
    }
}