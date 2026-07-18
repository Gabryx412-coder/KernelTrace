//! Probe per il signal monitoring: `kill`.
//!
//! Utile per correlare invii di segnali sospetti (es. `SIGKILL` inviato a
//! processi di sicurezza/monitoring da parte di un processo non
//! privilegiato, pattern comune di evasion).

use aya_ebpf::{macros::tracepoint, programs::TracePointContext};

use kerneltrace_common::events::{EventType, SignalEvent};

use super::process::build_header;
use crate::maps::EVENTS;

const SYS_ENTER_ARG0_OFFSET: usize = 16; // pid
const SYS_ENTER_ARG1_OFFSET: usize = 24; // sig

/// Probe su `syscalls:sys_enter_kill`.
#[tracepoint]
pub fn probe_kill(ctx: TracePointContext) -> u32 {
    match try_probe_kill(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_probe_kill(ctx: &TracePointContext) -> Result<u32, i64> {
    let header = build_header(EventType::Signal);

    let target_pid: i32 = ctx.read_at(SYS_ENTER_ARG0_OFFSET).map_err(|_| -1i64)?;
    let signal: i32 = ctx.read_at(SYS_ENTER_ARG1_OFFSET).map_err(|_| -1i64)?;

    let event = SignalEvent {
        header,
        target_pid,
        signal,
    };

    match EVENTS.reserve::<SignalEvent>(0) {
        Some(mut entry) => {
            entry.write(event);
            entry.submit(0);
        }
        None => {}
    }

    Ok(0)
}