# FAQ — Domande frequenti

## Generali

**KernelTrace sostituisce un antivirus tradizionale?**
No. KernelTrace è un Host Intrusion Detection System (HIDS): rileva
comportamenti sospetti a runtime tramite osservazione del kernel
(syscall, file, rete, processi), non effettua scansione signature-based
di file statici come un antivirus tradizionale. I due strumenti sono
complementari.

**Perché eBPF invece di un modulo kernel custom?**
I programmi eBPF sono verificati dal kernel prima del caricamento
(garanzia di terminazione, assenza di accessi a memoria non validi),
eliminando la classe di bug più pericolosa di un modulo kernel tradizionale
(crash o vulnerabilità nel modulo che compromettono l'intero kernel). eBPF
inoltre non richiede patch o ricompilazione del kernel, ed è supportato
nativamente da tutti i kernel Linux moderni (≥ 4.x per le funzionalità di
base, ≥ 5.8 per le funzionalità usate da KernelTrace).

**KernelTrace funziona su kernel non-Linux (Windows, macOS, BSD)?**
No. eBPF è una tecnologia specifica del kernel Linux. Non ci sono piani
per il supporto di altri sistemi operativi.

## Performance

**Qual è l'overhead reale di KernelTrace?**
L'obiettivo di progetto è un overhead di sistema inferiore al 2%; la
validazione empirica su hardware di riferimento è documentata (o
in corso di documentazione) in
[docs/performance/benchmarks.md](docs/performance/benchmarks.md). Vedi
quel documento per la metodologia di misurazione consigliata sul proprio
ambiente.

**Perché il ring buffer scarta eventi invece di bloccare il processo?**
Bloccare la syscall di un processo monitorato in attesa che il ring
buffer si svuoti introdurrebbe una dipendenza diretta e imprevedibile
delle performance dell'intero sistema dalla velocità dell'agente
userspace — inaccettabile per un HIDS pensato per la produzione. La
scelta di progetto è quindi "best effort": un carico eccezionalmente alto
può causare la perdita di alcuni eventi, preferibile a un rallentamento
generale del sistema monitorato.

## Detection

**Le regole di detection possono generare falsi positivi?**
Sì, in particolare le euristiche statistiche (rilevamento di beaconing)
e le regole basate su pattern generici (es. shell interattive) possono
generare falsi positivi su strumenti amministrativi legittimi che
condividono lo stesso pattern (es. uno script di manutenzione che lancia
`bash -i` legittimamente). Le regole built-in sono pensate come punto di
partenza da ottimizzare per il proprio ambiente specifico, non come
verità assoluta.

**Come disabilito una regola built-in che genera troppi falsi positivi
per il mio ambiente?**
Imposta `enabled: false` nel file YAML della regola, oppure copiala in
una directory personalizzata con le condizioni modificate e rimuovi la
directory `builtin_rules` da `rules.directories` nella tua
configurazione.

## Container e Kubernetes

**KernelTrace vede dentro i container senza essere lui stesso in un
container?**
Sì: le probe eBPF osservano tutti i processi dell'host, inclusi quelli
in esecuzione dentro namespace di container diversi, perché operano a
livello kernel, sotto l'astrazione dei container stessi. Non serve
installare un agente per ogni container.

**Perché il nome del pod Kubernetes non appare negli eventi?**
Il nome leggibile del pod non è derivabile dal solo cgroup path
(che contiene solo l'UID del pod); la risoluzione completa tramite
Kubelet API è pianificata, vedi [ROADMAP.md](ROADMAP.md).

## Sviluppo e contribuzione

**Posso scrivere plugin per KernelTrace?**
È predisposta un'interfaccia (`api::Plugin`), ma il caricamento dinamico
non è ancora implementato: i plugin attuali richiedono di essere
compilati staticamente insieme all'agente. Vedi
[ROADMAP.md](ROADMAP.md).

**Come propongo una nuova regola di detection?**
Vedi [docs/rules/writing-rules.md](docs/rules/writing-rules.md) e la
sezione dedicata in [CONTRIBUTING.md](CONTRIBUTING.md).