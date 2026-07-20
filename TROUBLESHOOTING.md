# Troubleshooting

## L'agente non si avvia: "insufficient privileges"

KernelTrace richiede `CAP_BPF` e `CAP_SYS_ADMIN` (o l'esecuzione come
root) per caricare programmi eBPF.

```bash
sudo kerneltrace-cli start --config /etc/kerneltrace/kerneltrace.yaml
```

Se esegui l'agente come servizio systemd senza root, verifica che l'unit
file conceda le capability necessarie (`AmbientCapabilities=CAP_BPF
CAP_SYS_ADMIN` in `deployment/systemd/kerneltrace.service`).

## Errore di caricamento eBPF: "invalid argument" o simile

Cause comuni:

1. **Kernel troppo vecchio**: verifica `uname -r` ≥ 5.8. Kernel più
   vecchi non supportano il ring buffer BPF (`BPF_MAP_TYPE_RINGBUF`,
   introdotto in 5.8) usato da KernelTrace.
2. **`vmlinux.h` non generato o non corrispondente al kernel in
   esecuzione**: rigenera con `./scripts/generate-vmlinux.sh` sull'host
   target, non su una macchina di build diversa.
3. **BTF non disponibile**: verifica che `/sys/kernel/btf/vmlinux` esista;
   se assente, il kernel non è stato compilato con `CONFIG_DEBUG_INFO_BTF=y`,
   requisito per CO-RE.

## Nessun evento viene rilevato nonostante l'agente sia in esecuzione

1. Verifica che le probe siano effettivamente attaccate:
```bash
   sudo bpftool prog list | grep kerneltrace
```
2. Verifica che `monitoring.*` non sia disabilitato nella configurazione
   attiva:
```bash
   kerneltrace-cli config show --config /etc/kerneltrace/kerneltrace.yaml
```
3. Verifica i log dell'agente per errori di attach silenziosi:
```bash
   sudo journalctl -u kerneltrace -f
```

## Il File Integrity Monitoring segnala continuamente lo stesso file

Se un file cambia legittimamente e frequentemente (es. un log applicativo
per errore incluso in `fim_watch_paths`), rimuovilo dal path monitorato o
richiama esplicitamente il refresh della baseline dopo una modifica
attesa (funzionalità di refresh via CLI pianificata, vedi
[ROADMAP.md](ROADMAP.md); nel frattempo un riavvio dell'agente
ricostruisce la baseline da zero).

## Overhead di sistema più alto del previsto

1. Verifica la dimensione del ring buffer (`RING_BUFFER_SIZE_BYTES` in
   `kerneltrace-common::constants`): un buffer troppo piccolo per il
   volume di eventi del tuo host può causare retry/backpressure eccessivi.
2. Riduci `fim_watch_paths` a directory realmente critiche, evitando di
   monitorare directory con alto tasso di scrittura (es. `/tmp` o
   directory di log applicative).
3. Consulta [docs/performance/benchmarks.md](docs/performance/benchmarks.md)
   per la metodologia di misurazione e confronto.

## Il tool Python (`kerneltrace-mgmt`) non trova il file di eventi

Verifica che `output.sinks` includa `json` e che `output.file_path` sia
configurato correttamente nella configurazione dell'agente — il tool
Python legge solo il file prodotto dal sink `json`, non comunica
direttamente con l'agente via socket o API di rete in questa fase del
progetto.

## Come ottenere ulteriore aiuto

Se il problema persiste, apri una issue usando il template
[bug report](.github/ISSUE_TEMPLATE/bug_report.yml), includendo output di
`uname -a`, versione di KernelTrace, e log rilevanti.