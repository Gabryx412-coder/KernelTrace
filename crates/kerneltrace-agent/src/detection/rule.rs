//! Schema delle regole di detection, deserializzato dai file YAML in
//! `detection/builtin_rules/` e da eventuali directory community
//! configurate in `rules.directories`.

use serde::{Deserialize, Serialize};

/// Severità di una regola, usata per prioritizzare gli alert negli output
/// sink e in eventuali integrazioni SIEM future.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Operatore di confronto applicato al valore di un campo estratto
/// dall'evento normalizzato.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operator {
    /// Uguaglianza esatta (case-insensitive per i campi testuali).
    Equals,
    /// Il valore del campo contiene la sottostringa indicata.
    Contains,
    /// Il valore del campo corrisponde all'espressione regolare indicata.
    Regex,
    /// Il valore del campo è presente in una lista separata da virgole.
    In,
    /// Il campo (tipicamente un tag) è presente sull'evento.
    Present,
}

/// Singola condizione di matching su un campo dell'evento normalizzato.
///
/// I campi supportati (vedi `matcher::extract_field`) includono, tra gli
/// altri: `event_kind`, `process.comm`, `process.parent_comm`,
/// `exec.filename`, `exec.args`, `network.dst_port`, `tag`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldCondition {
    pub field: String,
    pub operator: Operator,
    /// Valore di confronto; ignorato per l'operatore `present`.
    #[serde(default)]
    pub value: String,
}

/// Chiave di correlazione usata dalle regole sequenziali per associare
/// due eventi appartenenti allo stesso "contesto" (es. stesso processo
/// padre, per catturare `curl` e `chmod` lanciati dallo stesso script).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationKey {
    /// Correla eventi con lo stesso PID (stesso processo).
    Pid,
    /// Correla eventi con lo stesso PPID (stesso processo padre, es.
    /// comandi successivi in uno stesso script di shell).
    Ppid,
}

/// Specifica di matching di una regola: un singolo evento che soddisfa
/// tutte le condizioni (AND logico), oppure una sequenza di due eventi
/// correlati entro una finestra temporale.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MatchSpec {
    /// Tutte le condizioni devono essere soddisfatte dallo stesso evento.
    Simple { conditions: Vec<FieldCondition> },
    /// Un evento che soddisfa `first`, seguito entro `within_seconds` da
    /// un evento correlato (secondo `correlate_by`) che soddisfa `then`.
    Sequence {
        first: Vec<FieldCondition>,
        then: Vec<FieldCondition>,
        within_seconds: u64,
        correlate_by: CorrelationKey,
    },
}

/// Una regola di detection completa, come definita in un file YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub severity: Severity,
    #[serde(rename = "match")]
    pub match_spec: MatchSpec,
    /// Tag applicati all'evento quando la regola scatta, oltre al tag
    /// standard `rule:<id>` sempre aggiunto automaticamente dal motore.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Se `false`, la regola viene caricata ma non valutata (utile per
    /// disabilitare temporaneamente una regola senza rimuoverla dal file).
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserializes_simple_rule_from_yaml() {
        let yaml = r#"
id: test-rule
name: Test Rule
severity: high
match:
  kind: simple
  conditions:
    - field: process.comm
      operator: equals
      value: bash
tags:
  - test_tag
"#;
        let rule: Rule = serde_yaml::from_str(yaml).expect("should parse");
        assert_eq!(rule.id, "test-rule");
        assert_eq!(rule.severity, Severity::High);
        assert!(rule.enabled);
        match rule.match_spec {
            MatchSpec::Simple { conditions } => assert_eq!(conditions.len(), 1),
            _ => panic!("expected Simple match spec"),
        }
    }

    #[test]
    fn deserializes_sequence_rule_from_yaml() {
        let yaml = r#"
id: test-sequence
name: Test Sequence
severity: medium
match:
  kind: sequence
  first:
    - field: exec.filename
      operator: contains
      value: curl
  then:
    - field: exec.filename
      operator: contains
      value: chmod
  within_seconds: 30
  correlate_by: ppid
"#;
        let rule: Rule = serde_yaml::from_str(yaml).expect("should parse");
        match rule.match_spec {
            MatchSpec::Sequence {
                within_seconds,
                correlate_by,
                ..
            } => {
                assert_eq!(within_seconds, 30);
                assert_eq!(correlate_by, CorrelationKey::Ppid);
            }
            _ => panic!("expected Sequence match spec"),
        }
    }

    #[test]
    fn severity_ordering_is_correct() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
    }
}