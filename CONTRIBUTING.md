# Contribuire a KernelTrace

Grazie per l'interesse a contribuire a KernelTrace! Questo documento
descrive il processo per proporre modifiche, segnalare bug e sviluppare
nuove funzionalità.

## Prima di iniziare

- Leggi il [Codice di Condotta](CODE_OF_CONDUCT.md).
- Per vulnerabilità di sicurezza, **non aprire una issue pubblica**: segui
  la procedura in [SECURITY.md](SECURITY.md).
- Consulta la [Roadmap](ROADMAP.md) per capire se la tua idea è già
  pianificata o in discussione.

## Setup dell'ambiente di sviluppo

```bash
git clone https://github.com/gabryxdev/KernelTrace.git
cd KernelTrace
./scripts/setup-dev-env.sh
```

Vedi [docs/development/building.md](docs/development/building.md) per il
dettaglio del processo di build a due stadi (nightly per eBPF, stable per
l'agente).

## Workflow Git

1. Fai un fork del repository e crea un branch dedicato dal tuo fork:
   `feature/<nome-breve>` per nuove funzionalità, `fix/<nome-breve>` per
   bug fix.
2. Fai commit atomici, con messaggi nel formato
   [Conventional Commits](https://www.conventionalcommits.org/)
   (`feat(scope): descrizione`, `fix(scope): descrizione`,
   `docs(scope): descrizione`, ecc.), coerentemente con la cronologia del
   progetto.
3. Assicurati che `cargo fmt --all -- --check` e
   `cargo clippy --workspace --all-targets -- -D warnings` non riportino
   errori.
4. Assicurati che tutti i test passino: `cargo test --workspace --exclude kerneltrace-ebpf`.
5. Apri una pull request verso `main`, compilando il
   [template della PR](.github/PULL_REQUEST_TEMPLATE.md).

## Linee guida per il codice

- Rust idiomatico: preferisci `Result`/`Option` a `panic!`/`unwrap()` nel
  codice di produzione (eccezioni ragionevoli nei test).
- Ogni modulo pubblico deve avere documentazione (`///` sui commenti
  pubblici, `//!` a livello di modulo).
- Ogni nuova funzionalità deve includere test (unitari e, quando
  applicabile, di integrazione in `tests/integration/`).
- Le modifiche ai programmi eBPF (`crates/kerneltrace-ebpf`) devono
  rispettare i vincoli `no_std` e i limiti del BPF verifier — vedi
  [docs/development/debugging-ebpf.md](docs/development/debugging-ebpf.md).

## Contribuire con regole di detection

Le regole community vivono in `rules/community/`. Prima di proporre una
regola:

1. Validala con `kerneltrace-cli rules validate` o
   `kerneltrace-mgmt rules validate`.
2. Includi una `description` chiara del pattern di attacco rilevato.
3. Se possibile, aggiungi un test in stile
   `tests/integration/test_rules_engine.rs` che dimostri sia un caso
   positivo che uno negativo (per evitare falsi positivi non voluti).

Vedi [docs/rules/writing-rules.md](docs/rules/writing-rules.md) per la
guida completa.

## Processo di review

- Il progetto è attualmente mantenuto da un singolo maintainer (vedi
  [GOVERNANCE.md](GOVERNANCE.md)): ogni pull request è revisionata e
  approvata direttamente dal maintainer.
- La CI (build, test, lint, security audit) deve passare prima del merge.
- Il maintainer può richiedere modifiche o chiarimenti; rispondi ai
  commenti di review direttamente sulla PR.

## Segnalare bug

Usa il [template di bug report](.github/ISSUE_TEMPLATE/bug_report.yml),
includendo versione del kernel, distribuzione, versione di KernelTrace, e
passi per riprodurre il problema.

## Proporre funzionalità

Usa il [template di feature request](.github/ISSUE_TEMPLATE/feature_request.yml).
Le funzionalità che richiedono modifiche architetturali significative
beneficiano di una discussione preliminare in una issue prima
dell'implementazione.
