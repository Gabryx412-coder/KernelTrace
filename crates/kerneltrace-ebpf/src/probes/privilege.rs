//! Probe per il privilege monitoring: `ptrace`, `setuid`, `setgid`.

use aya_ebpf::{macros::tracepoint, programs::TracePointContext};

use kerneltrace_common::events::{EventType, PrivilegeChangeEvent, PtraceEvent};

use super::process::build_header;
use crate::maps::EVENTS;

const SYS_ENTER_ARG0_OFFSET: usize = 16;
const SYS_ENTER_ARG1_OFFSET: usize = 24;

/// Probe su `syscalls:sys_enter_ptrace`, rilevante per process injection
/// detection (`PTRACE_POKETEXT`, `PTRACE_ATTACH`, ecc. su processi altrui).
#[tracepoint]
pub fn probe_ptrace(ctx: TracePointContext) -> u32 {
    match try_probe_ptrace(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_probe_ptrace(ctx: &TracePointContext) -> Result<u32, i64> {
    let header = build_header(EventType::Ptrace);

    let request: i64 = ctx.read_at(SYS_ENTER_ARG0_OFFSET).map_err(|_| -1i64)?;
    let target_pid: i64 = ctx.read_at(SYS_ENTER_ARG1_OFFSET).map_err(|_| -1i64)?;

    let event = PtraceEvent {
        header,
        request,
        target_pid: target_pid as u32,
        _padding: [0u8; 4],
    };

    match EVENTS.reserve::<PtraceEvent>(0) {
        Some(mut entry) => {
            entry.write(event);
            entry.submit(0);
        }
        None => {}
    }

    Ok(0)
}

/// Costruisce e invia un `PrivilegeChangeEvent` comune a `setuid`/`setgid`.
fn emit_privilege_change(new_uid: Option<u32>, new_gid: Option<u32>) {
    let header = build_header(EventType::PrivilegeChange);

    let old_uid = header.uid;
    let old_gid = header.gid;
    let effective_new_uid = new_uid.unwrap_or(old_uid);
    let effective_new_gid = new_gid.unwrap_or(old_gid);

    let escalated_to_root =
        (effective_new_uid == 0 && old_uid != 0) || (effective_new_gid == 0 && old_gid != 0);

    let event = PrivilegeChangeEvent {
        header,
        old_uid,
        new_uid: effective_new_uid,
        old_gid,
        new_gid: effective_new_gid,
        escalated_to_root: escalated_to_root as u8,
        _padding: [0u8; 7],
    };

    if let Some(mut entry) = EVENTS.reserve::<PrivilegeChangeEvent>(0) {
        entry.write(event);
        entry.submit(0);
    }
}

/// Probe su `syscalls:sys_enter_setuid`.
#[tracepoint]
pub fn probe_setuid(ctx: TracePointContext) -> u32 {
    let new_uid: u32 = ctx.read_at::<i32>(SYS_ENTER_ARG0_OFFSET).unwrap_or(-1) as u32;
    emit_privilege_change(Some(new_uid), None);
    0
}

/// Probe su `syscalls:sys_enter_setgid`.
#[tracepoint]
pub fn probe_setgid(ctx: TracePointContext) -> u32 {
    let new_gid: u32 = ctx.read_at::<i32>(SYS_ENTER_ARG0_OFFSET).unwrap_or(-1) as u32;
    emit_privilege_change(None, Some(new_gid));
    0
}