<div align="center">

# KernelTrace

**A modern, high-performance Host Intrusion Detection System (HIDS) built on eBPF.**

[![CI](https://github.com/gabryxdev/KernelTrace/actions/workflows/ci.yml/badge.svg)](https://github.com/gabryxdev/KernelTrace/actions/workflows/ci.yml)
[![Clippy](https://github.com/gabryxdev/KernelTrace/actions/workflows/clippy.yml/badge.svg)](https://github.com/gabryxdev/KernelTrace/actions/workflows/clippy.yml)
[![Security Audit](https://github.com/gabryxdev/KernelTrace/actions/workflows/security-audit.yml/badge.svg)](https://github.com/gabryxdev/KernelTrace/actions/workflows/security-audit.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.79%2B-orange.svg)](rust-toolchain.toml)

[Documentazione](docs/README.md) ·
[Quickstart](docs/getting-started/quickstart.md) ·
[Architettura](docs/architecture/overview.md) ·
[Contribuire](CONTRIBUTING.md) ·
[Roadmap](ROADMAP.md)

</div>

---

## Cos'è KernelTrace

**KernelTrace** è un Host Intrusion Detection System (HIDS) di nuova generazione, costruito
interamente su **eBPF** con tecnica **CO-RE (Compile Once – Run Everywhere)**. È pensato per
essere eseguito in produzione su server Linux moderni, ambienti containerizzati (Docker,
Podman, Kubernetes) e infrastrutture cloud, offrendo visibilità in tempo reale a livello
kernel con un overhead di sistema **inferiore al 2%**.

A differenza degli HIDS tradizionali basati su polling, log parsing o moduli kernel custom,
KernelTrace osserva gli eventi **direttamente alla fonte** — syscall, operazioni sul
filesystem, connessioni di rete, eventi di processo — tramite probe eBPF sicuri e verificati
dal kernel stesso, senza necessità di patch o moduli kernel out-of-tree.

> ⚠️ **Stato del progetto**: KernelTrace è in sviluppo attivo. Le API e il formato di
> configurazione possono cambiare prima della release `1.0`. Consulta [ROADMAP.md](ROADMAP.md)
> per lo stato delle funzionalità.

## Perché KernelTrace


|
|
|
|
---
|
---
|
|
 🚀 
**
Overhead minimo
**
|
 Target di progetto: overhead CPU/memoria inferiore al 2% grazie a probe eBPF ottimizzate e pipeline asincrona zero-copy dove possibile 
|
|
 🔬 
**
Visibilità a livello kernel
**
|
 Tracciamento di syscall critiche (
`execve`
, 
`connect`
, 
`ptrace`
, 
`mmap`
, ecc.) senza modifiche al kernel 
|
|
 📦 
**
Container-aware
**
|
 Riconoscimento automatico di container Docker, Podman e pod Kubernetes tramite cgroup e namespace 
|
|
 📜 
**
Rules engine dichiarativo
**
|
 Regole di detection scritte in YAML, leggibili e versionabili come codice 
|
|
 🧩 
**
Architettura modulare
**
|
 Ogni componente (probe, pipeline, detection, output) è un modulo indipendente e testabile 
|
|
 🔌 
**
Estensibile
**
|
 Trait pubblici pensati per aggiungere in futuro anomaly detection ML, risposta automatica, e integrazioni SIEM (Elastic, Splunk, Grafana, Prometheus) senza riscrivere il core 
|
|
 🛡️ 
**
CO-RE
**
|
 Un singolo binario eBPF compilato una volta, eseguibile su kernel diversi senza ricompilazione 
|

## Funzionalità principali

- **Syscall monitoring**: `execve`, `execveat`, `open`, `openat`, `connect`, `accept`, `bind`,
  `listen`, `clone`, `fork`, `vfork`, `ptrace`, `mmap`, `chmod`, `chown`, `unlink`, `rename`,
  `kill`, `mount`, `umount`, `setuid`, `setgid`
- **File Integrity Monitoring (FIM)**: creazione, modifica, eliminazione, rename, cambi di
  permessi e owner
- **Network monitoring**: connessioni TCP/UDP su IPv4/IPv6, euristiche per reverse shell e
  beaconing
- **Process monitoring**: process tree, relazioni parent-child, processi orfani/zombie,
  rilevamento privilege escalation
- **Container awareness**: Docker, Podman, Kubernetes
- **Rules engine YAML**: regole built-in per reverse shell, shell spawnate da processi web,
  pattern `curl | chmod`, socket Python sospetti, `nc`/`socat`, download sospetti
- **Architettura pronta per il futuro**: anomaly detection ML, risposta automatica (kill,
  blocco IP, quarantena container), integrazioni SIEM — predisposte via trait, non ancora
  implementate

Consulta [docs/architecture/overview.md](docs/architecture/overview.md) per il dettaglio
tecnico completo.

## Struttura del repository

crates/
├── kerneltrace-common/ # Tipi condivisi kernel <-> userspace
├── kerneltrace-ebpf/ # Programmi eBPF (probe, CO-RE)
├── kerneltrace-agent/ # Agente principale (Rust + tokio)
└── kerneltrace-cli/ # CLI di gestione

management/ # Tool di management in Python
rules/ # Regole di detection YAML
docs/ # Documentazione completa
deployment/ # systemd, Docker, Kubernetes
