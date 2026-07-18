//! # kerneltrace-common
//!
//! Crate condiviso tra i programmi eBPF (`crates/kerneltrace-ebpf`, `no_std`)
//! e l'agente userspace (`crates/kerneltrace-agent`, `std`).
//!
//! Contiene:
//! - [`events`]: le struct `#[repr(C)]` degli eventi raw scritti nel ring buffer BPF;
//! - [`syscalls`]: l'enum [`SyscallId`] con l'elenco delle syscall monitorate;
//! - [`constants`]: i limiti fissi condivisi tra probe e agente;
//! - [`error`]: il tipo di errore comune [`CommonError`].
//!
//! ## Perché `no_std`
//!
//! I programmi eBPF non hanno accesso alla libreria standard di Rust: girano
//! in un sandbox verificato dal kernel, senza allocatore di default e con
//! uno stack limitato a 512 byte per programma. Questo crate è quindi
//! `no_std` di default; la feature `std` viene abilitata esclusivamente dal
//! lato userspace per ottenere `serde::Serialize`/`Deserialize` sugli eventi
//! e l'implementazione di `std::error::Error` su [`CommonError`].
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]
#![allow(clippy::missing_safety_doc)]

// I test (cfg(test)) girano sempre con std disponibile, indipendentemente
// dalla feature `std` del crate, quindi `extern crate alloc` nei moduli di
// test non richiede ulteriori configurazioni.

pub mod constants;
pub mod error;
pub mod events;
pub mod syscalls;

pub use constants::*;
pub use error::CommonError;
pub use events::{
    EventHeader, EventType, ExecEvent, FileEvent, MmapEvent, MountEvent, NetworkEvent,
    PrivilegeChangeEvent, ProcessLifecycleEvent, PtraceEvent, SignalEvent,
};
pub use syscalls::SyscallId;