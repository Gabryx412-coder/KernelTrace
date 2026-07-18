//! Modulo aggregatore delle probe eBPF.
//!
//! Ogni sotto-modulo raggruppa le probe per dominio funzionale (processo,
//! file, rete, privilegi, memoria, segnali, mount) e viene registrato in
//! `main.rs`.

pub mod file;
pub mod memory;
pub mod mount;
pub mod network;
pub mod privilege;
pub mod process;
pub mod signal;