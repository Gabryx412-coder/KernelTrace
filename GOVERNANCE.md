# Governance

## Struttura del progetto

KernelTrace è attualmente mantenuto da un singolo maintainer
([@Gabryx412-coder](https://github.com/Gabryx412-coder)), su un account
GitHub personale. Questo documento descrive il modello di governance
attuale e come evolverà se il progetto crescerà fino ad accogliere più
collaboratori con diritto di merge.

## Modello attuale: single maintainer

- Tutte le decisioni tecniche e di processo sono prese dal maintainer.
- Le pull request esterne sono benvenute e revisionate secondo le linee
  guida in [CONTRIBUTING.md](CONTRIBUTING.md); l'approvazione finale e il
  merge restano una responsabilità del maintainer.
- Le decisioni di sicurezza sono gestite privatamente secondo il processo
  in [SECURITY.md](SECURITY.md).

## Evoluzione futura

Se il progetto crescerà oltre un singolo maintainer, questo documento
verrà aggiornato per riflettere:

- Un modello **maintainer-led** con più persone aventi diritto di merge
  su aree specifiche del codice (analogo a quanto già predisposto, a
  livello di intenzione, in [CODEOWNERS](.github/CODEOWNERS))
- Un processo esplicito per proporre nuovi maintainer
- L'eventuale passaggio del repository a un'organizzazione GitHub, per
  poter sfruttare team dedicati per area (eBPF, agente, regole di
  detection, documentazione, CI/CD)

## Come proporsi come collaboratore

Se vuoi contribuire regolarmente al progetto, apri o commenta una issue,
oppure proponi pull request di qualità costante: il maintainer valuterà
caso per caso l'opportunità di concedere accesso di collaborazione più
ampio.

## Modifiche a questo documento

Finché il progetto resta a maintainer singolo, le modifiche a questo
documento sono decise direttamente dal maintainer.