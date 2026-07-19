# Riferimento campi e operatori delle regole

## Campi disponibili (`field`)

| Campo | Applicabile a | Descrizione |
|---|---|---|
| `event_kind` | tutti | Tipo di evento (`exec`, `connect`, `file_change`, ecc.) |
| `process.comm` | tutti | Nome del processo |
| `process.parent_comm` | tutti (se risolto) | Nome del processo padre |
| `process.uid` | tutti | UID effettivo del processo |
| `process.pid` | tutti | PID del processo |
| `tag` | tutti | Tag già applicati da enricher precedenti |
| `exec.filename` | `exec` | Path dell'eseguibile |
| `exec.args` | `exec` | Argomenti concatenati con spazio |
| `exec.command_line` | `exec` | `filename` + `args` concatenati |
| `network.dst_port` | eventi di rete | Porta di destinazione |
| `network.dst_addr` | eventi di rete | Indirizzo IP di destinazione |
| `file.path` | eventi di file | Path del file coinvolto |

Un campo non applicabile al tipo di evento corrente rende la condizione
automaticamente non soddisfatta (non un errore).

## Operatori (`operator`)

| Operatore | Semantica |
|---|---|
| `equals` | Uguaglianza esatta, case-insensitive |
| `contains` | Il campo contiene la sottostringa (case-insensitive) |
| `regex` | Il campo corrisponde all'espressione regolare in `value` |
| `in` | Il campo è presente in una lista `value` separata da virgole |
| `present` | Il tag indicato in `value` è presente su `event.tags` (ignora `field`) |

## Severità (`severity`)

`low` < `medium` < `high` < `critical`. Influenza il livello di log
emesso quando la regola scatta (`critical`/`high` → `error`, `medium` →
`warn`, `low` → `info`).

## Correlazione nelle regole `sequence`

| `correlate_by` | Semantica |
|---|---|
| `pid` | Correla eventi con lo stesso PID (stesso processo) |
| `ppid` | Correla eventi con lo stesso PPID (stesso processo padre, es. comandi in uno stesso script) |

`within_seconds` definisce la finestra temporale massima tra l'evento
`first` e l'evento `then` perché la regola scatti.

## Tag applicati automaticamente

Ogni regola che scatta applica il tag `rule:<id>` all'evento, oltre agli
eventuali tag custom elencati in `tags`. Questi tag sono visibili
nell'output JSON e utilizzabili da altre regole tramite l'operatore
`present` su `field: tag`.