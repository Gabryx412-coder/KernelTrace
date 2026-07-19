# Scrivere regole di detection custom

Le regole KernelTrace sono file YAML dichiarativi, caricati dalle
directory configurate in `rules.directories`.

## Struttura minima

```yaml
id: my-custom-rule
name: Descrizione breve leggibile
severity: high   # low | medium | high | critical
match:
  kind: simple
  conditions:
    - field: process.comm
      operator: equals
      value: bash
tags:
  - my_custom_tag
enabled: true
```

## Regole "simple": tutte le condizioni su un singolo evento

Ogni condizione in `conditions` deve essere soddisfatta (AND logico)
dallo **stesso evento** perché la regola scatti. Vedi
[rule-reference.md](rule-reference.md) per l'elenco completo dei campi e
operatori disponibili.

```yaml
id: python-in-tmp
name: Python interpreter executed from /tmp
severity: medium
match:
  kind: simple
  conditions:
    - field: event_kind
      operator: equals
      value: exec
    - field: exec.filename
      operator: regex
      value: "^/tmp/.*python"
```

## Regole "sequence": due eventi correlati nel tempo

Utile per pattern come "download seguito da esecuzione", dove nessun
singolo evento è di per sé sospetto, ma la loro combinazione lo è.

```yaml
id: download-then-execute
name: File downloaded then executed shortly after
severity: high
match:
  kind: sequence
  first:
    - field: exec.filename
      operator: contains
      value: wget
  then:
    - field: exec.filename
      operator: contains
      value: /tmp/
  within_seconds: 60
  correlate_by: ppid   # oppure "pid"
```

`correlate_by: ppid` correla eventi generati da processi figli dello
stesso script/shell; `correlate_by: pid` correla eventi dello stesso
processo.

## Testare una regola prima del deploy

```bash
# Con la CLI Rust (validazione autoritativa, identica a quella applicata
# dall'agente al caricamento):
kerneltrace-cli rules validate --config kerneltrace.yaml

# Con il tool Python (validazione strutturale leggera, utile in CI senza
# toolchain Rust):
kerneltrace-mgmt rules validate ./rules/community/
```

## Convenzioni per le regole community

- Usa un prefisso descrittivo per `id` (es. `community-<nome-univoco>`)
  per distinguerle dalle regole `builtin-*`.
- Aggiungi sempre `description` con il razionale della regola.
- Preferisci tag standard MITRE ATT&CK quando applicabile (es.
  `mitre_t1059`) per facilitare la correlazione con altri strumenti.
- Testa la regola contro eventi sia positivi che negativi prima di
  proporla come pull request (vedi `tests/integration/test_rules_engine.rs`
  per esempi).