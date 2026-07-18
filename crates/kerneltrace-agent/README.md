# kerneltrace-agent

L'agente userspace di KernelTrace: carica i programmi eBPF, consuma il ring
buffer degli eventi, li normalizza e arricchisce, li valuta contro il rules
engine, e li invia agli output sink configurati (stdout, file, JSON).

## Moduli

| Modulo | Responsabilità |
|---|---|
| `config/` | Caricamento e validazione della configurazione YAML |
| `loader/` | Attach dei programmi eBPF tramite `aya`, lettura del ring buffer |
| `events/` | Pipeline eventi: normalizzazione, arricchimento, canale asincrono |
| `process/` | Process tree, orphan/zombie detection, privilege escalation *(Parte 5)* |
| `fim/` | File Integrity Monitoring *(Parte 7)* |
| `network/` | Connection tracking, reverse shell, beaconing *(Parte 8)* |
| `container/` | Container awareness (Docker/Podman/K8s) *(Parte 9)* |
| `detection/` | Rules engine *(Parte 10)* |
| `anomaly/` | Trait per anomaly detection ML futura *(Parte 12)* |
| `response/` | Trait per risposta automatica futura *(Parte 12)* |
| `output/` | Sink di output (JSON, stdout, file) *(Parte 11)* |
| `telemetry/` | Setup di `tracing`/`tracing-subscriber` |
| `api/` | Trait per estensibilità futura (plugin) *(Parte 12)* |

## Flusso dati

eBPF ring buffer
│
▼
loader::ringbuf_reader   (lettura asincrona, zero-copy dal buffer BPF)
│
▼
events::normalizer       (byte grezzi -> evento tipizzato)
│
▼
events::enrichment       (process tree, container, hash file, ecc.)
│
▼
events::pipeline         (canale tokio::mpsc con backpressure)
│
▼
detection::engine        (valutazione regole YAML)
│
▼
output::sink_trait       (JSON su stdout/file, futuro: Elastic/Splunk/Kafka)
