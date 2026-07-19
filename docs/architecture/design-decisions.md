# Decisioni di design

## Perché un ring buffer condiviso invece di una mappa per tipo di evento

Un singolo `RingBuf` condiviso tra tutte le probe (campo `event_type`
nell'header come discriminante) semplifica l'ordinamento cronologico lato
userspace: l'agente legge un unico stream di byte invece di dover fondere
più stream con lock o `select!` multipli. Il costo è un piccolo overhead
di branching nel parsing (`match event_type`), trascurabile rispetto al
beneficio di semplicità.

## Perché l'ordine degli Enricher nella pipeline è significativo

`ContainerResolver` viene sempre per primo perché il contesto container
che popola è potenzialmente consultato dagli enricher successivi (regole
differenziate per processi containerizzati). Il `DetectionEngine` viene
sempre per ultimo perché molte regole built-in dipendono da tag applicati
da altri stadi (`tag: suspected_reverse_shell` dal modulo network,
`process.parent_comm` dal process tree). Invertire l'ordine romperebbe
silenziosamente queste regole senza errori di compilazione, per questo
l'ordine è documentato esplicitamente qui oltre che nei commenti di
`main.rs`.

## Perché il PPID di `exec` è risolto lato userspace

Il tracepoint `sched_process_exec` non espone il PID del processo padre
nel proprio formato stabile. Anziché usare un kprobe fragile su una
funzione interna del kernel per ottenerlo, manteniamo un process tree in
userspace costruito dagli eventi di fork/clone/vfork (che invece
espongono `parent_pid` nel formato del tracepoint `sched_process_fork`),
e lo consultiamo per arricchire retroattivamente gli eventi di exec. Il
costo è un piccolo ritardo se l'evento di fork non è ancora stato
processato quando arriva l'exec corrispondente (raro in pratica, dato
l'ordine tipico fork→exec sulla stessa CPU).

## Perché BLAKE3 come default per il FIM

BLAKE3 è significativamente più veloce di SHA-256 a parità di garanzie
crittografiche rilevanti per il nostro caso d'uso (rilevare modifiche non
autorizzate, non produrre digest per verifiche legali/compliance esterne).
Per deployment che richiedono compatibilità con strumenti esterni che si
aspettano SHA-256, l'algoritmo è configurabile per singolo deployment.

## Perché le azioni di risposta sono dry-run by default

Un'azione di risposta automatica errata (kill di un processo di
produzione, blocco di un IP legittimo) può causare un incidente più grave
di quello che tentava di prevenire. `ResponseSettings::default()` ha
`enabled: false` e `dry_run: true`: un operatore deve **esplicitamente e
doppiamente** attivare le azioni reali, un compromesso deliberato a favore
della sicurezza operativa rispetto alla comodità.

## Perché il rules engine è dichiarativo (YAML) e non un DSL Rust

Le regole di detection cambiano più frequentemente del codice
dell'agente e sono tipicamente scritte/riviste da analisti di sicurezza,
non necessariamente da sviluppatori Rust. Un formato YAML dichiarativo
permette di versionare le regole come configurazione, distribuirle
separatamente dal binario, e validarle in CI senza ricompilare l'agente
(vedi `kerneltrace-mgmt rules validate`).