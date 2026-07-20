# Esempio: regola di detection custom

Questo esempio mostra `custom_rule.yaml`, una regola completa e commentata
riga per riga che rileva la modifica di file crontab di sistema da parte
di processi non privilegiati — un pattern comune di persistenza usato
dagli attacker dopo una compromissione iniziale.

## Come attivarla

1. Copia il file in una directory monitorata:
```bash
   sudo mkdir -p /etc/kerneltrace/rules
   sudo cp custom_rule.yaml /etc/kerneltrace/rules/
```

2. Aggiungi la directory alla configurazione dell'agente:
```yaml
   rules:
     directories:
       - /etc/kerneltrace/rules
```

3. Valida la regola prima di riavviare l'agente:
```bash
   kerneltrace-cli rules validate --config /etc/kerneltrace/kerneltrace.yaml
```

4. Riavvia l'agente:
```bash
   sudo systemctl restart kerneltrace
```

## Nota sulla condizione `process.uid`

Come indicato nel commento del file YAML, l'esempio usa l'operatore `in`
con una lista di UID di esempio; in un caso reale converrebbe piuttosto
una condizione "diverso da root", non ancora supportata come operatore
diretto (vedi [ROADMAP.md](../../ROADMAP.md) — un operatore `not_equals`
è una funzionalità ragionevole da proporre come contributo).

## Vedi anche

- [docs/rules/writing-rules.md](../../docs/rules/writing-rules.md) — guida completa
- [docs/rules/rule-reference.md](../../docs/rules/rule-reference.md) — riferimento campi/operatori