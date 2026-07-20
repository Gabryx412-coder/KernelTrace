## Descrizione

<!-- Descrivi cosa cambia questa PR e perché. -->

## Tipo di modifica

- [ ] Bug fix (modifica non-breaking che risolve un problema)
- [ ] Nuova funzionalità (modifica non-breaking che aggiunge funzionalità)
- [ ] Breaking change (fix o funzionalità che cambia il comportamento esistente)
- [ ] Documentazione
- [ ] Nuova regola di detection / modifica a regola esistente
- [ ] Modifica a CI/CD o tooling

## Area del progetto interessata

- [ ] eBPF / probe kernel (`crates/kerneltrace-ebpf`)
- [ ] Agente userspace (`crates/kerneltrace-agent`)
- [ ] Rules engine / regole (`detection/`, `rules/`)
- [ ] CLI Rust (`crates/kerneltrace-cli`)
- [ ] Tool Python (`management/`)
- [ ] Documentazione (`docs/`)
- [ ] CI/CD (`.github/workflows/`)

## Checklist

- [ ] Il codice segue le linee guida in [CONTRIBUTING.md](../CONTRIBUTING.md)
- [ ] `cargo fmt --all -- --check` passa senza errori
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passa senza errori
- [ ] Ho aggiunto test che coprono la modifica (unitari e/o di integrazione)
- [ ] Tutti i test esistenti passano (`cargo test --workspace --exclude kerneltrace-ebpf`)
- [ ] Ho aggiornato la documentazione rilevante (se applicabile)
- [ ] Ho aggiunto una voce a `CHANGELOG.md` sotto `[Unreleased]` (se applicabile)
- [ ] Se questa PR aggiunge una regola di detection, ho incluso sia un
      caso positivo che uno negativo nei test

## Come è stato testato

<!-- Descrivi come hai verificato che la modifica funzioni correttamente. -->

## Issue collegate

<!-- Es. "Closes #123" o "Relates to #456" -->