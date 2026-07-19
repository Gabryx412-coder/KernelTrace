//! Rules engine: schema delle regole, parser YAML, matcher e motore di
//! valutazione applicato come stadio di arricchimento della pipeline.

pub mod engine;
pub mod matcher;
pub mod parser;
pub mod rule;

pub use engine::DetectionEngine;
pub use parser::{load_all_rules, load_rule_file, load_rules_from_directory};
pub use rule::{CorrelationKey, FieldCondition, MatchSpec, Operator, Rule, Severity};