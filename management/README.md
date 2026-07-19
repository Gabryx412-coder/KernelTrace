# kerneltrace-mgmt

Tool di management in Python per KernelTrace: CLI complementare a
`kerneltrace-cli` (Rust), pensata per compiti di gestione operativa che
beneficiano dell'ecosistema Python (scripting, integrazione con strumenti
di automazione esistenti, validazione rapida di regole prima del deploy).

## Installazione

```bash
cd management
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Comandi

```bash
# Segue in tempo reale il file di eventi JSON prodotto dal sink `json`
# dell'agente, con evidenziazione a colori per severità.
kerneltrace-mgmt tail /var/log/kerneltrace/events.json

# Valida tutte le regole YAML in una directory prima di distribuirle
kerneltrace-mgmt rules validate ./rules/community/

# Elenca le regole in una directory con un riepilogo tabellare
kerneltrace-mgmt rules list ./rules/community/

# Valida un file di configurazione dell'agente
kerneltrace-mgmt config validate /etc/kerneltrace/kerneltrace.yaml
```

## Perché un tool separato dalla CLI Rust

`kerneltrace-cli` (Rust) resta l'interfaccia primaria e privilegiata per
avviare/fermare l'agente e ispezionarne lo stato in tempo reale.
`kerneltrace-mgmt` (Python) si concentra invece su compiti che tipicamente
girano **fuori dall'host monitorato** — ad esempio in una pipeline CI che
valida le regole di un merge request prima che vengano distribuite, o su
una workstation di un analista SOC che consulta i log raccolti — dove non
è necessario né desiderabile avere Rust/Cargo installato.

## Struttura del pacchetto

| Modulo | Responsabilità |
|---|---|
| `cli.py` | Entry point e definizione dei comandi (`click`) |
| `client.py` | Lettura del flusso di eventi JSON prodotto dall'agente |
| `rules_manager.py` | Parsing e validazione delle regole YAML (mirror dello schema Rust) |
| `config_validator.py` | Validazione strutturale della configurazione YAML dell'agente |