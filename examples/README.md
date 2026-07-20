# Esempi

Questa directory contiene esempi standalone che dimostrano come integrare
o estendere KernelTrace usando `kerneltrace-agent` come libreria.

| Esempio | Dimostra |
|---|---|
| [`basic_monitoring/`](basic_monitoring/) | Uso minimo della pipeline: caricamento eBPF, normalizzazione eventi, stampa su stdout, senza rules engine né output sink configurabili |
| [`custom_rule/`](custom_rule/) | Una regola di detection custom completa, con spiegazione riga per riga |
| [`custom_sink/`](custom_sink/) | Implementazione di un `Sink` custom (invio eventi verso un webhook HTTP locale) |

## Eseguire un esempio

```bash
cd examples/basic_monitoring
sudo cargo run --release
```

Ogni esempio richiede gli stessi privilegi dell'agente principale
(`CAP_BPF`/`CAP_SYS_ADMIN` o root), dato che carica gli stessi programmi
eBPF tramite `kerneltrace-agent::loader`.

## Perché questi esempi sono esclusi dal workspace principale

Come gli altri crate binari standalone, `basic_monitoring` e
`custom_sink` sono elencati in `exclude` nel `Cargo.toml` radice (vedi
Parte 1 dello sviluppo): questo evita che le loro dipendenze specifiche
(es. un client HTTP nell'esempio del sink custom) vengano risolte anche
per una `cargo build` ordinaria del workspace principale, mantenendo il
grafo di dipendenze dell'agente e della CLI il più snello possibile.