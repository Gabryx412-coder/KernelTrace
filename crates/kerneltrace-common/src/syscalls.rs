//! Identificatori delle syscall monitorate da KernelTrace.
//!
//! Questo enum non rispecchia i numeri di syscall reali del kernel (che
//! variano per architettura); è invece un identificatore interno stabile
//! usato per etichettare gli eventi generati dalle probe eBPF e per
//! referenziare le syscall nelle regole YAML del rules engine.

#![allow(clippy::upper_case_acronyms)]

/// Identificatore stabile di una syscall monitorata da KernelTrace.
///
/// `repr(u32)` per poter essere scritto direttamente nelle struct evento
/// `#[repr(C)]` condivise con i programmi eBPF.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyscallId {
    Execve = 0,
    Execveat = 1,
    Open = 2,
    Openat = 3,
    Connect = 4,
    Accept = 5,
    Bind = 6,
    Listen = 7,
    Clone = 8,
    Fork = 9,
    Vfork = 10,
    Ptrace = 11,
    Mmap = 12,
    Chmod = 13,
    Chown = 14,
    Unlink = 15,
    Rename = 16,
    Kill = 17,
    Mount = 18,
    Umount = 19,
    Setuid = 20,
    Setgid = 21,
}

impl SyscallId {
    /// Restituisce il nome canonico della syscall, usato per il campo
    /// `syscall` nei log JSON e per il matching nelle regole YAML.
    pub const fn name(&self) -> &'static str {
        match self {
            SyscallId::Execve => "execve",
            SyscallId::Execveat => "execveat",
            SyscallId::Open => "open",
            SyscallId::Openat => "openat",
            SyscallId::Connect => "connect",
            SyscallId::Accept => "accept",
            SyscallId::Bind => "bind",
            SyscallId::Listen => "listen",
            SyscallId::Clone => "clone",
            SyscallId::Fork => "fork",
            SyscallId::Vfork => "vfork",
            SyscallId::Ptrace => "ptrace",
            SyscallId::Mmap => "mmap",
            SyscallId::Chmod => "chmod",
            SyscallId::Chown => "chown",
            SyscallId::Unlink => "unlink",
            SyscallId::Rename => "rename",
            SyscallId::Kill => "kill",
            SyscallId::Mount => "mount",
            SyscallId::Umount => "umount",
            SyscallId::Setuid => "setuid",
            SyscallId::Setgid => "setgid",
        }
    }
}

impl TryFrom<u32> for SyscallId {
    type Error = crate::error::CommonError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SyscallId::Execve),
            1 => Ok(SyscallId::Execveat),
            2 => Ok(SyscallId::Open),
            3 => Ok(SyscallId::Openat),
            4 => Ok(SyscallId::Connect),
            5 => Ok(SyscallId::Accept),
            6 => Ok(SyscallId::Bind),
            7 => Ok(SyscallId::Listen),
            8 => Ok(SyscallId::Clone),
            9 => Ok(SyscallId::Fork),
            10 => Ok(SyscallId::Vfork),
            11 => Ok(SyscallId::Ptrace),
            12 => Ok(SyscallId::Mmap),
            13 => Ok(SyscallId::Chmod),
            14 => Ok(SyscallId::Chown),
            15 => Ok(SyscallId::Unlink),
            16 => Ok(SyscallId::Rename),
            17 => Ok(SyscallId::Kill),
            18 => Ok(SyscallId::Mount),
            19 => Ok(SyscallId::Umount),
            20 => Ok(SyscallId::Setuid),
            21 => Ok(SyscallId::Setgid),
            other => Err(crate::error::CommonError::UnknownSyscallId(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_all_variants() {
        let variants = [
            SyscallId::Execve,
            SyscallId::Execveat,
            SyscallId::Open,
            SyscallId::Openat,
            SyscallId::Connect,
            SyscallId::Accept,
            SyscallId::Bind,
            SyscallId::Listen,
            SyscallId::Clone,
            SyscallId::Fork,
            SyscallId::Vfork,
            SyscallId::Ptrace,
            SyscallId::Mmap,
            SyscallId::Chmod,
            SyscallId::Chown,
            SyscallId::Unlink,
            SyscallId::Rename,
            SyscallId::Kill,
            SyscallId::Mount,
            SyscallId::Umount,
            SyscallId::Setuid,
            SyscallId::Setgid,
        ];

        for variant in variants {
            let raw = variant as u32;
            let parsed = SyscallId::try_from(raw).expect("valore valido");
            assert_eq!(parsed as u32, raw);
        }
    }

    #[test]
    fn unknown_id_returns_error() {
        let result = SyscallId::try_from(9999);
        assert!(result.is_err());
    }

    #[test]
    fn names_are_lowercase_and_non_empty() {
        assert_eq!(SyscallId::Execve.name(), "execve");
        assert_eq!(SyscallId::Setgid.name(), "setgid");
    }
}