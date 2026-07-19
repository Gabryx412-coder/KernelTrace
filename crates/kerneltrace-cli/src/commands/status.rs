//! Comando `kerneltrace-cli status`: verifica se l'agente è in esecuzione
//! consultando il PID file, senza richiedere privilegi elevati.

use std::path::PathBuf;

use kerneltrace_agent::config;
use serde::Serialize;

use crate::output_format::{print_json, OutputFormat};

#[derive(Debug, Serialize)]
struct AgentStatus {
    running: bool,
    pid: Option<i32>,
    pid_file: String,
}

/// Verifica se il processo indicato dal PID file è realmente in
/// esecuzione, per distinguere un PID file "stantio" (rimasto da un
/// crash precedente, non ripulito) da un agente effettivamente attivo.
fn is_process_alive(pid: i32) -> bool {
    use nix::sys::signal::kill;
    use nix::unistd::Pid;

    // L'invio del segnale 0 non termina né influenza il processo: è
    // l'idioma POSIX standard per verificarne solo l'esistenza.
    kill(Pid::from_raw(pid), None).is_ok()
}

fn read_pid_file(path: &std::path::Path) -> Option<i32> {
    std::fs::read_to_string(path)
        .ok()?
        .trim()
        .parse::<i32>()
        .ok()
}

pub fn run(config_path: Option<PathBuf>, format: OutputFormat) -> anyhow::Result<()> {
    let config_path = config_path.unwrap_or_else(config::default_config_path);
    let pid_file = config::load_config(&config_path)
        .map(|cfg| cfg.agent.pid_file)
        .unwrap_or_else(|_| config::default_config().agent.pid_file);

    let pid = read_pid_file(&pid_file);
    let running = pid.map(is_process_alive).unwrap_or(false);

    let status = AgentStatus {
        running,
        pid: if running { pid } else { None },
        pid_file: pid_file.display().to_string(),
    };

    match format {
        OutputFormat::Json => print_json(&status)?,
        OutputFormat::Table => {
            if status.running {
                println!("KernelTrace agent: RUNNING (pid {})", status.pid.unwrap());
            } else {
                println!("KernelTrace agent: NOT RUNNING");
            }
            println!("PID file: {}", status.pid_file);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_pid_file_parses_valid_pid() {
        let dir = tempfile::tempdir().unwrap();
        let pid_path = dir.path().join("kerneltrace.pid");
        std::fs::write(&pid_path, "12345\n").unwrap();

        assert_eq!(read_pid_file(&pid_path), Some(12345));
    }

    #[test]
    fn read_pid_file_returns_none_for_missing_file() {
        assert_eq!(read_pid_file(std::path::Path::new("/nonexistent/kerneltrace.pid")), None);
    }

    #[test]
    fn read_pid_file_returns_none_for_malformed_content() {
        let dir = tempfile::tempdir().unwrap();
        let pid_path = dir.path().join("kerneltrace.pid");
        std::fs::write(&pid_path, "not-a-pid").unwrap();

        assert_eq!(read_pid_file(&pid_path), None);
    }

    #[test]
    fn is_process_alive_returns_true_for_current_process() {
        let current_pid = std::process::id() as i32;
        assert!(is_process_alive(current_pid));
    }

    #[test]
    fn is_process_alive_returns_false_for_implausible_pid() {
        // PID estremamente alto, con altissima probabilità inesistente su
        // qualunque sistema Linux reale.
        assert!(!is_process_alive(i32::MAX - 1));
    }
}