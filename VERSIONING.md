# Versioning Policy

KernelTrace segue [Semantic Versioning 2.0.0](https://semver.org/lang/it/)
a partire dalla release `1.0.0`.

## Durante la fase `0.x` (pre-1.0)

Come da convenzione SemVer, durante la fase `0.x` l'API e il formato di
configurazione **possono cambiare in modo incompatibile anche in release
minori** (`0.1.0` → `0.2.0`). Ogni cambiamento incompatibile è comunque
documentato esplicitamente in [CHANGELOG.md](CHANGELOG.md) sotto una
sezione `### Changed` o `### Removed`, con istruzioni di migrazione
quando applicabile.

## Dopo la release `1.0.0`

- **MAJOR** (`X.0.0`): cambiamenti incompatibili all'API pubblica dei
  crate Rust, al formato di configurazione YAML, o allo schema delle
  regole di detection.
- **MINOR** (`0.X.0`): nuove funzionalità retrocompatibili (nuove probe,
  nuovi campi di configurazione opzionali, nuove regole built-in).
- **PATCH** (`0.0.X`): correzioni di bug retrocompatibili, aggiornamenti
  di sicurezza, ottimizzazioni di performance senza cambi comportamentali.

## Cosa è considerato parte dell'API pubblica stabile

- Lo schema YAML della configurazione (`kerneltrace-agent::config::schema`)
- Lo schema YAML delle regole di detection (`kerneltrace-agent::detection::rule`)
- Il formato JSON degli eventi normalizzati emessi dal sink `json`
- I comandi e le opzioni di `kerneltrace-cli`
- Le API pubbliche dei trait di estensibilità (`Enricher`, `Sink`,
  `AnomalyEngine`, `ResponseAction`, `Plugin`)

## Cosa NON è coperto da garanzie di stabilità

- I dettagli interni delle probe eBPF (offset dei tracepoint, nomi delle
  sezioni ELF)
- La struttura interna del ring buffer BPF (formato `#[repr(C)]` delle
  struct in `kerneltrace-common`)
- I dettagli implementativi non esposti tramite l'API pubblica dei crate

## Politica di supporto delle versioni

Vedi [SECURITY.md](SECURITY.md) per la politica di supporto di sicurezza
delle versioni pubblicate.