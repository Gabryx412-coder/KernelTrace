//! Probe per il memory monitoring: `mmap`.
//!
//! Usata principalmente come euristica di process injection detection:
//! mappature contemporaneamente scrivibili ed eseguibili (RWX) sono un
//! pattern comune di shellcode injection e code caching di loader
//! malevoli. La classificazione del pattern avviene lato userspace
//! (`detection::builtin_rules`); questa probe si limita a catturare i
//! flag richiesti senza logica di detection in kernel-space.

use aya_ebpf::{macros::tracepoint, programs::TracePointContext};

use kerneltrace_common::events::{EventType, MmapEvent};

use super::process::build_header;
use crate::maps::EVENTS;

const SYS_ENTER_ARG0_OFFSET: usize = 16; // addr
const SYS_ENTER_ARG1_OFFSET: usize = 24; // length
const SYS_ENTER_ARG2_OFFSET: usize = 32; // prot
const SYS_ENTER_ARG3_OFFSET: usize = 40; // flags

/// Probe su `syscalls:sys_enter_mmap`.
#[tracepoint]
pub fn probe_mmap(ctx: TracePointContext) -> u32 {
    match try_probe_mmap(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_probe_mmap(ctx: &TracePointContext) -> Result<u32, i64> {
    let header = build_header(EventType::Mmap);

    let addr: u64 = ctx.read_at(SYS_ENTER_ARG0_OFFSET).unwrap_or(0);
    let length: u64 = ctx.read_at(SYS_ENTER_ARG1_OFFSET).unwrap_or(0);
    let prot_flags: i32 = ctx.read_at(SYS_ENTER_ARG2_OFFSET).unwrap_or(0);
    let map_flags: i32 = ctx.read_at(SYS_ENTER_ARG3_OFFSET).unwrap_or(0);

    let event = MmapEvent {
        header,
        addr,
        length,
        prot_flags: prot_flags as u32,
        map_flags: map_flags as u32,
    };

    match EVENTS.reserve::<MmapEvent>(0) {
        Some(mut entry) => {
            entry.write(event);
            entry.submit(0);
        }
        None => {}
    }

    Ok(0)
}