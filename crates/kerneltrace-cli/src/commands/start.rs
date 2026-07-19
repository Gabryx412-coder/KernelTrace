//! Comando `kerneltrace-cli start`: avvia l'agente `kerneltrace-agent`
//! come processo figlio, propagando il file di configurazione tramite la
//! variabile d'ambiente `KERNELTRACE_CONFIG` (la stessa letta da
//! `kerneltrace-agent::main`).

use std::path::PathBuf;
use std::process::{Command, Stdio};

use tracing::info;

/// Nome del binario dell'agente da cercare nel `PATH`, oppure accanto
/// all'eseguibile della CLI stessa (caso comune per installazioni locali
/// non ancora pacchettizzate su tutto il sistema).
const AGENT_BINARY_NAME: &str = "kerneltrace-agent";

/// Determina il percorso dell'eseguibile dell'agente: prima cerca accanto
/// al binario della CLI corrente (utile in sviluppo, quando entrambi i
/// binari sono nella stessa directory `target/release`), poi fa
/// affidamento sulla risoluzione del `PATH` di sistema.
fn resolve_agent_binary() -> PathBuf {
    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(dir) = current_exe.parent() {
            let candidate = dir.join(AGENT_BINARY_NAME);
            if candidate.exists() {
                return candidate;
            }
        }
    }
    PathBuf::from(AGENT_BINARY_NAME)
}

/// Avvia l'agente, opzionalmente in background (`detach`). In modalità
/// foreground (default), il processo della CLI resta in attesa e inoltra
/// il codice di uscita dell'agente; utile per l'esecuzione sotto systemd
/// (`Type=simple`), dove il process supervisor si aspetta che il processo
/// principale resti in foreground.
pub fn run(config_path: Option<PathBuf>, detach: bool) -> anyhow::Result<()> {
    let agent_binary = resolve_agent_binary();

    info!(agent_binary = %agent_binary.display(), detach, "starting KernelTrace agent");

    let mut command = Command::new(&agent_binary);

    if let Some(path) = &config_path {
        command.env("KERNELTRACE_CONFIG", path);
    }

    if detach {
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let child = command.spawn().map_err(|err| {
            anyhow::anyhow!("failed to spawn agent binary at {}: {err}", agent_binary.display())
        })?;

        println!("KernelTrace agent started in background (pid {})", child.id());
        Ok(())
    } else {
        let status = command.status().map_err(|err| {
            anyhow::anyhow!("failed to execute agent binary at {}: {err}", agent_binary.display())
        })?;

        if !status.success() {
            anyhow::bail!(
                "KernelTrace agent exited with non-zero status: {}",
                status
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_agent_binary_falls_back_to_path_lookup() {
        // In assenza di un binario reale accanto all'eseguibile di test,
        // la funzione deve comunque restituire un path (risolto poi dal
        // PATH di sistema al momento dell'esecuzione), senza panicare.
        let path = resolve_agent_binary();
        assert!(!path.as_os_str().is_empty());
    }
}