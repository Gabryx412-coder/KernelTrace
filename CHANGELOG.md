# Changelog

Tutte le modifiche rilevanti a questo progetto sono documentate in questo
file.

Il formato è basato su [Keep a Changelog](https://keepachangelog.com/it/1.0.0/),
e questo progetto aderisce al [Semantic Versioning](https://semver.org/lang/it/)
(vedi [VERSIONING.md](VERSIONING.md) per il dettaglio applicato durante la
fase `0.x`).

## [Unreleased]

### Added
- Struttura iniziale del progetto: workspace Cargo, crate
  `kerneltrace-common`, `kerneltrace-ebpf`, `kerneltrace-agent`,
  `kerneltrace-cli`.
- Probe eBPF per process, file, network, privilege, memory, signal e
  mount monitoring.
- Pipeline eventi asincrona con arricchimento componibile (container
  awareness, process tree, File Integrity Monitoring, network
  detection).
- Rules engine dichiarativo YAML con supporto a regole singole e
  sequenziali, incluse 6 regole built-in (reverse shell, shell da web
  server, curl→chmod, socket scripting, netcat/socat, download
  pipe-to-shell).
- Output sink stdout/file/JSON Lines.
- Predisposizione architetturale per anomaly detection ML, risposta
  automatica (dry-run by default), e plugin di terze parti.
- CLI Rust (`kerneltrace-cli`) e tool di management Python
  (`kerneltrace-mgmt`).
- Suite di test: unitari, integrazione, benchmark (`criterion`), fuzzing
  (`cargo-fuzz`).
- CI/CD completa: build, lint, formattazione, benchmark, security audit,
  CodeQL, documentazione, fuzzing, release multi-arch.
- Documentazione completa: architettura, guide operative, riferimento
  regole, deployment (Docker/Kubernetes/bare-metal).

### Known limitations
- Overhead di sistema `< 2%` non ancora validato empiricamente su
  hardware di riferimento (vedi
  [docs/performance/benchmarks.md](docs/performance/benchmarks.md)).
- Nome e namespace dei pod Kubernetes non risolti (solo UID del pod).
- Baseline FIM non persistente tra riavvii dell'agente.

[Unreleased]: https://github.com/gabryxdev/KernelTrace/compare/main...HEAD
