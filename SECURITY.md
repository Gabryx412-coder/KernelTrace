# Security Policy

## Segnalare una vulnerabilità

KernelTrace è un sistema di sicurezza (HIDS) e le vulnerabilità che ne comprometterebbero
l'affidabilità vanno segnalate con la massima cura.

**Non aprire una issue pubblica per vulnerabilità di sicurezza.**

Segnala invece privatamente tramite:

1. **GitHub Security Advisories** (metodo preferito): usa la funzione
   ["Report a vulnerability"](https://github.com/Gabryx412-coder/KernelTrace/security/advisories/new)
   nella tab Security del repository.

Questo è attualmente l'unico canale di segnalazione ufficiale del progetto.

## Cosa aspettarsi

- **Conferma di ricezione**: entro 3 giorni lavorativi.
- **Valutazione iniziale**: entro 7 giorni lavorativi, con una prima
  stima di severità (basata su CVSS) e tempistiche.
- **Coordinamento della disclosure**: lavoriamo con chi segnala per
  concordare tempistiche di disclosure responsabile, tipicamente 90
  giorni dalla conferma, salvo necessità di coordinamento più ampio.

## Versioni supportate

| Versione | Supportata |
|---|---|
| 0.x (pre-1.0) | ✅ Solo l'ultima release minore |
| < 0.1 | ❌ |

Fino alla release `1.0`, il supporto di sicurezza è limitato all'ultima
versione minore pubblicata; non manteniamo backport su versioni `0.x`
precedenti data la fase di sviluppo attivo.

## Ambito

Sono considerate vulnerabilità di sicurezza in ambito, tra le altre:

- Bug nei programmi eBPF che permettono di bypassare il BPF verifier o
  causare comportamenti indefiniti nel kernel
- Bypass del rules engine che permettono a un attacker di evitare la
  detection in modo affidabile e riproducibile
- Vulnerabilità di parsing (regole YAML, configurazione) che permettono
  denial-of-service o esecuzione di codice
- Privilege escalation tramite l'agente stesso (es. se l'agente, girando
  come root, potesse essere indotto a scrivere file arbitrari)

Non sono considerati vulnerabilità di sicurezza (ma benvenuti come bug
report regolari): falsi positivi/negativi occasionali del rules engine
dovuti a euristiche intrinsecamente imperfette (es. il rilevamento di
beaconing o reverse shell è statistico/euristico per natura).

## Crediti

Con il consenso di chi segnala, accreditiamo pubblicamente i ricercatori
di sicurezza nelle release notes della versione che corregge la
vulnerabilità.