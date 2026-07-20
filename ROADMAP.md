# Roadmap

Questo documento traccia le funzionalità pianificate ma non ancora
implementate, insieme a limiti noti dell'implementazione attuale. Non è
un impegno con scadenze fisse, ma riflette la direzione del progetto.

## Verso la 1.0

- [ ] Comando `kerneltrace-cli stop` (attualmente solo `start`)
- [ ] Persistenza della baseline FIM tra riavvii dell'agente (attualmente
      in memoria, ricostruita da zero a ogni avvio)
- [ ] Risoluzione del nome e namespace dei pod Kubernetes tramite Kubelet
      API locale (attualmente solo UID del pod, derivato dal cgroup path)
- [ ] Pulizia automatica della cache di `ContainerResolver` alla
      terminazione dei processi (attualmente non collegata allo scanner
      di lifecycle)
- [ ] Validazione empirica dell'obiettivo di overhead `< 2%` su hardware
      di riferimento, con risultati pubblicati in
      `docs/performance/benchmarks.md`

## Anomaly detection (ML)

- [ ] Prima implementazione concreta di `anomaly::AnomalyEngine`
      (l'interfaccia esiste già, vedi Parte 12 dello sviluppo)
- [ ] Valutazione tra approcci basati su statistiche (baseline
      comportamentale per host) vs. modelli più sofisticati (autoencoder,
      classificatori sequenziali sulla process tree)
- [ ] Integrazione del punteggio di anomalia come tag consultabile dal
      rules engine

## Risposta automatica

- [ ] Prima azione di risposta reale (non logging-only): kill del
      processo, dietro conferma esplicita e configurazione granulare
- [ ] Blocco IP (integrazione con `nftables`/`iptables`)
- [ ] Quarantena container (pausa/isolamento di rete del container via
      Docker/Podman/CRI API)
- [ ] Audit trail dettagliato di ogni azione di risposta eseguita

## Integrazioni SIEM e osservabilità

- [ ] Sink verso Elasticsearch (client HTTP diretto, oltre al pattern
      JSON Lines + Filebeat già supportato)
- [ ] Sink verso Splunk HEC (HTTP Event Collector)
- [ ] Esportatore metriche Prometheus (numero di eventi per tipo, regole
      scattate, overhead di sistema)
- [ ] Dashboard Grafana di esempio

## Management e usabilità

- [ ] Caricamento dinamico di plugin (`api::Plugin`) tramite librerie
      condivise o WASM, oltre alle implementazioni Rust statiche attuali
- [ ] UI web di management (sostituendo/affiancando la sola CLI)
- [ ] Comando `kerneltrace-mgmt` per l'inoltro diretto verso SIEM esterni

## Copertura di monitoraggio

- [ ] Correlazione esplicita `accept`/`bind` con l'indirizzo effettivo
      (attualmente arricchito tramite lettura di `/proc/<pid>/net/tcp{,6}`
      pianificata ma non ancora implementata in dettaglio)
- [ ] Supporto per architetture aggiuntive oltre x86_64/aarch64

## Come proporre l'aggiunta di una voce

Apri una issue con il template
[feature request](.github/ISSUE_TEMPLATE/feature_request.yml); le
proposte discusse e accettate vengono aggiunte a questo documento dai
maintainer.