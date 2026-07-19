# Riferimento configurazione

Il file di configurazione è in formato YAML. Tutti i campi hanno un
valore di default; il file può quindi essere anche vuoto (`{}`) per un
comportamento completamente di default.

## `agent`

| Campo | Tipo | Default | Descrizione |
|---|---|---|---|
| `hostname` | string, opzionale | hostname di sistema | Nome host riportato negli eventi |
| `pipeline_capacity` | intero | `8192` | Dimensione del canale interno (backpressure) |
| `pid_file` | path | `/run/kerneltrace.pid` | File PID del processo demonizzato |

## `logging`

| Campo | Tipo | Default | Descrizione |
|---|---|---|---|
| `level` | string | `info` | Livello minimo (`trace`/`debug`/`info`/`warn`/`error`), sintassi `EnvFilter` |
| `format` | `json`\|`pretty`\|`compact` | `json` | Formato dei log |
| `directory` | path, opzionale | assente | Directory per log su file rotante; se assente, solo stdout |

## `monitoring`

| Campo | Tipo | Default | Descrizione |
|---|---|---|---|
| `process` | bool | `true` | Abilita process monitoring |
| `file_integrity` | bool | `true` | Abilita File Integrity Monitoring |
| `network` | bool | `true` | Abilita network monitoring |
| `syscalls` | bool | `true` | Abilita monitoraggio syscall generico |
| `fim_watch_paths` | lista di path | `[]` | Path monitorati dal FIM (file singoli o directory) |
| `fim_hash_algorithm` | `sha256`\|`blake3` | `blake3` | Algoritmo di hashing per il FIM |

## `rules`

| Campo | Tipo | Default | Descrizione |
|---|---|---|---|
| `directories` | lista di path | `[builtin_rules]` | Directory contenenti regole `.yaml`/`.yml` |
| `strict_parsing` | bool | `false` | Se `true`, un errore di parsing su una regola blocca l'avvio |

## `output`

| Campo | Tipo | Default | Descrizione |
|---|---|---|---|
| `sinks` | lista di `stdout`\|`file`\|`json` | `[stdout]` | Sink attivi |
| `file_path` | path, opzionale | assente | Richiesto se `file` o `json` sono in `sinks` |

## `container`

| Campo | Tipo | Default | Descrizione |
|---|---|---|---|
| `docker` | bool | `true` | Riconoscimento container Docker |
| `podman` | bool | `true` | Riconoscimento container Podman |
| `kubernetes` | bool | `true` | Riconoscimento pod Kubernetes |

## `response`

| Campo | Tipo | Default | Descrizione |
|---|---|---|---|
| `enabled` | bool | `false` | Abilita il modulo di risposta automatica |
| `dry_run` | bool | `true` | Se `true`, nessuna azione produce un effetto reale |

> ⚠️ In questa versione sono disponibili solo azioni "logging-only"
> (nessun effetto distruttivo reale è implementato). Vedi
> [ROADMAP.md](../../ROADMAP.md).

## Esempio completo

Vedi [`config/kerneltrace.example.yaml`](../../config/kerneltrace.example.yaml).

## Validazione

```bash
kerneltrace-cli config validate --config /path/to/kerneltrace.yaml
```

oppure, senza toolchain Rust:

```bash
kerneltrace-mgmt config validate /path/to/kerneltrace.yaml
```