"""kerneltrace_mgmt: management tooling for the KernelTrace HIDS agent.

Questo pacchetto fornisce una CLI Python complementare a `kerneltrace-cli`
(Rust), pensata per compiti operativi come la validazione delle regole
prima del deploy, l'ispezione del flusso di eventi JSON, e la validazione
della configurazione, eseguibili anche su macchine senza toolchain Rust.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]