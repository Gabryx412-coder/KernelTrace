# Benchmark e metodologia di performance

## Obiettivo dichiarato del progetto

KernelTrace punta a un overhead complessivo di sistema **inferiore al
2%** durante il monitoraggio attivo, misurato come degradazione delle
prestazioni di un carico di lavoro rappresentativo con l'agente attivo
rispetto allo stesso carico senza l'agente.

## Cosa misurano i benchmark `criterion` inclusi nel repository

I benchmark in `benches/` (`pipeline_bench`, `detection_bench`,
`ebpf_overhead_bench`) misurano **solo il costo userspace** di
normalizzazione, arricchimento e valutazione delle regole. Sono utili
per:

- Rilevare regressioni di performance introdotte da modifiche al codice
  (integrati in CI, vedi `.github/workflows/bench.yml`, con confronto
  storico automatico).
- Confrontare il costo relativo di normalizzazione vs. arricchimento vs.
  valutazione delle regole, per capire dove investire ottimizzazioni.

**Non misurano** l'overhead reale del sistema completo (che include il
costo delle probe eBPF nel kernel, i context switch, e l'effetto sul
carico di lavoro monitorato), per un limite intrinseco: `criterion`
esegue in un processo userspace ordinario, senza caricare eBPF nel
kernel.

## Metodologia per misurare l'overhead complessivo end-to-end

Per validare l'obiettivo `< 2%` dichiarato, si raccomanda:

1. **Baseline**: eseguire un carico di lavoro rappresentativo (es.
   `sysbench`, `stress-ng`, o un carico applicativo reale) senza
   KernelTrace attivo, misurando throughput/latenza con `perf stat`.
2. **Con KernelTrace**: ripetere lo stesso carico con l'agente in
   esecuzione e tutte le probe attaccate, misurando lo stesso set di
   metriche.
3. **Confronto**: calcolare la percentuale di degradazione per ciascuna
   metrica (throughput, latenza p50/p99, CPU aggregata).

```bash
# Esempio con sysbench CPU benchmark
sysbench cpu --threads=4 run > baseline.txt
sudo kerneltrace-cli start --config kerneltrace.yaml --detach
sysbench cpu --threads=4 run > with-agent.txt
sudo kerneltrace-cli stop  # comando pianificato, vedi ROADMAP.md
```

## Risultati attuali

> ⚠️ Questa sezione va popolata con risultati reali misurati sull'hardware
> di riferimento del progetto, non ancora disponibili in questa fase
> dello sviluppo. I numeri riportati nei benchmark automatici CI (vedi il
> badge Benchmark nel README) riflettono solo il costo userspace relativo,
> non l'overhead di sistema assoluto.

| Metrica | Baseline | Con KernelTrace | Overhead |
|---|---|---|---|
| _(da popolare)_ | | | |

## Interpretare i risultati di `cargo bench`

L'output di `criterion` riporta tempo medio per iterazione con intervallo
di confidenza. Un valore di riferimento indicativo per
`normalize_exec_event` su hardware moderno è nell'ordine di poche
centinaia di nanosecondi; un aumento significativo tra esecuzioni
successive del benchmark segnala una regressione da investigare prima di
un merge (rilevato automaticamente da `github-action-benchmark` in CI).