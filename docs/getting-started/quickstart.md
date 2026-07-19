# Quickstart

Questa guida presuppone che KernelTrace sia già installato (vedi
[installation.md](installation.md)).

## 1. Copia la configurazione di esempio

```bash
sudo mkdir -p /etc/kerneltrace
sudo cp config/kerneltrace.example.yaml /etc/kerneltrace/kerneltrace.yaml
```

Modifica `fim_watch_paths` per includere i path rilevanti per il tuo
sistema (es. `/etc/passwd`, `/etc/shadow`, directory di binari critici).

## 2. Valida la configurazione

```bash
kerneltrace-cli config validate --config /etc/kerneltrace/kerneltrace.yaml
```

## 3. Avvia l'agente

```bash
sudo kerneltrace-cli start --config /etc/kerneltrace/kerneltrace.yaml
```

L'agente resta in foreground, stampando gli eventi rilevati su stdout
(formato leggibile) e, se configurato, su file JSON Lines.

Per l'esecuzione come servizio persistente, vedi
[deployment/bare-metal.md](../deployment/bare-metal.md).

## 4. Genera un evento di test

In un altro terminale, sullo stesso host:

```bash
bash -c 'echo test'
```

Dovresti vedere un evento `Exec` apparire nell'output dell'agente.

## 5. Testa una regola di detection

```bash
# NON eseguire su un host di produzione: questo comando genera un evento
# che la regola built-in "netcat/socat exec" è progettata per rilevare.
nc -e /bin/sh 127.0.0.1 4444 &
```

L'agente dovrebbe loggare un evento con severità `critical` e tag
`rule:builtin-netcat-socat-exec`.

## 6. Ispeziona le regole caricate

```bash
kerneltrace-cli rules list
```

## Prossimi passi

- [Guida alla configurazione completa](configuration.md)
- [Scrivere regole custom](../rules/writing-rules.md)
- [Deployment in produzione](../deployment/)