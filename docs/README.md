# Documentazione KernelTrace

Indice della documentazione tecnica del progetto.

## Per iniziare

- [Installazione](getting-started/installation.md)
- [Quickstart](getting-started/quickstart.md)
- [Configurazione](getting-started/configuration.md)

## Architettura

- [Panoramica architetturale](architecture/overview.md)
- [Decisioni di design](architecture/design-decisions.md)
- Diagrammi: [architettura generale](architecture/diagrams/architecture.mmd), [event pipeline](architecture/diagrams/event-pipeline.mmd), [data flow](architecture/diagrams/data-flow.mmd)

## Regole di detection

- [Scrivere regole custom](rules/writing-rules.md)
- [Riferimento completo dei campi e operatori](rules/rule-reference.md)

## Deployment

- [Docker](deployment/docker.md)
- [Kubernetes](deployment/kubernetes.md)
- [Bare-metal / systemd](deployment/bare-metal.md)

## Sviluppo

- [Build del progetto](development/building.md)
- [Esecuzione dei test](development/testing.md)
- [Debug delle probe eBPF](development/debugging-ebpf.md)

## Performance

- [Metodologia e risultati di benchmark](performance/benchmarks.md)

## API

- [Riferimento API (rustdoc)](api/reference.md)

## Altro

- [FAQ](../FAQ.md)
- [Troubleshooting](../TROUBLESHOOTING.md)
- [Roadmap](../ROADMAP.md)