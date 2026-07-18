//! Modulo aggregatore delle probe eBPF.
//!
//! Ogni sotto-modulo raggruppa le probe per dominio funzionale (processo,
//! file, rete, ecc.) e viene registrato in `main.rs`. Solo `process` è
//! implementato in questa parte; gli altri moduli vengono aggiunti in una
//! parte successiva dedicata all'estensione delle probe eBPF.

pub mod process;

// Moduli pianificati, aggiunti in una parte successiva dello sviluppo:
// pub mod file;
// pub mod network;
// pub mod privilege;
// pub mod memory;
// pub mod signal;
// pub mod mount;