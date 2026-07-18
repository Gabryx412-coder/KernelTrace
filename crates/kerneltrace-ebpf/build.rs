//! Build script del crate `kerneltrace-ebpf`.
//!
//! Il compito principale è assicurarsi che `vmlinux.h` (generato da
//! `scripts/generate-vmlinux.sh` a partire da `bpftool btf dump`) sia
//! presente prima della compilazione, dato che è il file che rende
//! possibile la tecnica CO-RE (Compile Once - Run Everywhere): contiene i
//! layout delle struct del kernel corrente, usati da `aya-ebpf` per
//! generare accessi ai campi rilocabili a runtime dal verifier BPF.

use std::path::Path;

fn main() {
    let vmlinux_path = Path::new("../../vmlinux.h");

    if !vmlinux_path.exists() {
        println!(
            "cargo:warning=vmlinux.h non trovato in {}. Esegui \
             `./scripts/generate-vmlinux.sh` prima di compilare i programmi eBPF. \
             La build procederà comunque se `aya-ebpf` non richiede simboli da vmlinux.h \
             per le probe attualmente implementate.",
            vmlinux_path.display()
        );
    }

    println!("cargo:rerun-if-changed=../../vmlinux.h");
    println!("cargo:rerun-if-changed=src");
}