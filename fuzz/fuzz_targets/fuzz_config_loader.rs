//! Fuzz target per il caricamento della configurazione YAML.
//!
//! Obiettivo: verificare che la deserializzazione di `Config` (che usa
//! `#[serde(deny_unknown_fields)]` su strutture profondamente annidate)
//! non vada mai in panic su input arbitrario, incluse strutture YAML con
//! ricorsione/alias che potrebbero in teoria causare amplificazione
//! esponenziale durante il parsing.

#![no_main]

use kerneltrace_agent::config::Config;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    let _ = serde_yaml::from_str::<Config>(text);
});