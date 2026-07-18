//! Generazione della configurazione di default, esposta anche tramite
//! `kerneltrace-cli config --print-default` (Parte 13).

use super::schema::Config;

/// Restituisce la configurazione di default, identica a quella che si
/// otterrebbe deserializzando un file YAML vuoto.
pub fn default_config() -> Config {
    Config::default()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            agent: Default::default(),
            logging: Default::default(),
            monitoring: Default::default(),
            rules: Default::default(),
            output: Default::default(),
            container: Default::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_serializes_to_valid_yaml() {
        let config = default_config();
        let yaml = serde_yaml::to_string(&config).expect("serialization should succeed");
        assert!(yaml.contains("pipeline_capacity"));

        // Round-trip: la configurazione di default deve poter essere
        // riparsata senza errori (garantisce coerenza tra Default e Deserialize).
        let reparsed: Config = serde_yaml::from_str(&yaml).expect("round-trip should succeed");
        assert_eq!(reparsed.agent.pipeline_capacity, config.agent.pipeline_capacity);
    }
}