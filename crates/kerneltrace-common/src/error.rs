//! Errore comune, `no_std`-compatibile, usato dal crate `kerneltrace-common`.
//!
//! Non usiamo `thiserror` qui perché questo crate deve rimanere compilabile
//! per il target `bpfel-unknown-none` (nessuna libreria standard, nessun
//! allocatore). L'implementazione di `core::fmt::Display` è scritta a mano.

use core::fmt;

/// Errore restituito dalle funzioni di conversione/parsing di questo crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommonError {
    /// Un valore numerico non corrisponde a nessun `SyscallId` noto.
    UnknownSyscallId(u32),
    /// Un valore numerico non corrisponde a nessun `EventType` noto.
    UnknownEventType(u32),
    /// Un buffer di byte ricevuto dal ring buffer ha una dimensione
    /// inattesa rispetto alla struct che si tenta di leggere.
    UnexpectedBufferSize { expected: usize, actual: usize },
}

impl fmt::Display for CommonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommonError::UnknownSyscallId(id) => {
                write!(f, "unknown syscall id: {id}")
            }
            CommonError::UnknownEventType(kind) => {
                write!(f, "unknown event type: {kind}")
            }
            CommonError::UnexpectedBufferSize { expected, actual } => {
                write!(
                    f,
                    "unexpected buffer size: expected {expected} bytes, got {actual} bytes"
                )
            }
        }
    }
}

// `std::error::Error` è implementato solo quando la feature `std` è attiva,
// dato che il trait vive in `std::error` e non in `core`.
#[cfg(feature = "std")]
impl std::error::Error for CommonError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_messages_are_human_readable() {
        let err = CommonError::UnknownSyscallId(42);
        assert_eq!(err.to_string_no_std(), "unknown syscall id: 42");
    }

    // Helper minimale per testare `Display` senza dipendere da `alloc`/`std::string::String`
    // nel corpo del crate; nei test invece std è comunque disponibile (cfg(test) usa lo
    // harness di default che linka std), quindi possiamo usare `format!` in sicurezza.
    trait DisplayExt {
        fn to_string_no_std(&self) -> alloc::string::String;
    }

    extern crate alloc;

    impl DisplayExt for CommonError {
        fn to_string_no_std(&self) -> alloc::string::String {
            alloc::format!("{self}")
        }
    }
}