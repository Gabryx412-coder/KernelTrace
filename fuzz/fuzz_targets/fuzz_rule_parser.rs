//! Fuzz target per il parser delle regole YAML.
//!
//! Obiettivo: verificare che nessun input arbitrario (incluso YAML
//! malformato, profondamente annidato, o con tipi inattesi) causi panic o
//! comportamenti indefiniti nel parser di `kerneltrace-agent::detection`,
//! dato che questo parser elabora file YAML potenzialmente forniti da
//! terze parti (regole community).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Solo input UTF-8 validi hanno senso come YAML; input non-UTF-8 sono
    // scartati senza esercitare il parser, per concentrare il budget di
    // fuzzing su input strutturalmente plausibili.
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    // Il parsing non deve mai panicare, indipendentemente dal contenuto:
    // un errore di deserializzazione è un esito atteso e gestito
    // correttamente tramite Result, non un fallimento del fuzzing.
    let _ = serde_yaml::from_str::<kerneltrace_agent::detection::Rule>(text);
});