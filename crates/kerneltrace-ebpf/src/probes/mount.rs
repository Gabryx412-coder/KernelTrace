//! Probe per il monitoraggio di `mount`/`umount`, rilevante per detection
//! di tentativi di persistenza o evasione tramite filesystem overlay,
//! bind mount su path sensibili, o rimozione di filesystem di audit.

use aya_ebpf::{macros::tracepoint, programs::TracePointContext};

use kerneltrace_common::{
    constants::MAX_PATH_LEN,
    events::{EventType, MountEvent},
};

use super::process::build_header;
use crate::maps::EVENTS;

const SYS_ENTER_ARG0_OFFSET: usize = 16; // source (mount) / target (umount)
const SYS_ENTER_ARG1_OFFSET: usize = 24; // target (mount)
const SYS_ENTER_ARG2_OFFSET: usize = 32; // filesystemtype (mount)

#[inline(always)]
unsafe fn read_user_path_into(user_ptr: u64, dest: &mut [u8; MAX_PATH_LEN]) -> u16 {
    match aya_ebpf::helpers::gen::bpf_probe_read_user_str_bytes(user_ptr as *const u8, dest) {
        Ok(len) => len.min(MAX_PATH_LEN) as u16,
        Err(_) => 0,
    }
}

/// Probe su `syscalls:sys_enter_mount`.
#[tracepoint]
pub fn probe_mount(ctx: TracePointContext) -> u32 {
    match try_probe_mount(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_probe_mount(ctx: &TracePointContext) -> Result<u32, i64> {
    let header = build_header(EventType::Mount);

    let mut entry = match EVENTS.reserve::<MountEvent>(0) {
        Some(entry) => entry,
        None => return Ok(0),
    };

    let event = entry.as_mut_ptr();
    unsafe {
        (*event).header = header;
        (*event).source = [0u8; MAX_PATH_LEN];
        (*event).target = [0u8; MAX_PATH_LEN];
        (*event).filesystem_type = [0u8; 32];
        (*event).is_umount = 0;
        (*event)._padding = [0u8; 2];

        let source_ptr: u64 = ctx.read_at(SYS_ENTER_ARG0_OFFSET).map_err(|_| -1i64)?;
        (*event).source_len = read_user_path_into(source_ptr, &mut (*event).source);

        let target_ptr: u64 = ctx.read_at(SYS_ENTER_ARG1_OFFSET).map_err(|_| -1i64)?;
        (*event).target_len = read_user_path_into(target_ptr, &mut (*event).target);

        let fstype_ptr: u64 = ctx.read_at(SYS_ENTER_ARG2_OFFSET).unwrap_or(0);
        if fstype_ptr != 0 {
            let mut fstype_buf = [0u8; 32];
            if let Ok(len) = aya_ebpf::helpers::gen::bpf_probe_read_user_str_bytes(
                fstype_ptr as *const u8,
                &mut fstype_buf,
            ) {
                (*event).filesystem_type = fstype_buf;
                (*event).filesystem_type_len = len.min(32) as u8;
            }
        }
    }

    entry.submit(0);
    Ok(0)
}

/// Probe su `syscalls:sys_enter_umount` (copre `umount`/`umount2`).
#[tracepoint]
pub fn probe_umount(ctx: TracePointContext) -> u32 {
    match try_probe_umount(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_probe_umount(ctx: &TracePointContext) -> Result<u32, i64> {
    let header = build_header(EventType::Mount);

    let mut entry = match EVENTS.reserve::<MountEvent>(0) {
        Some(entry) => entry,
        None => return Ok(0),
    };

    let event = entry.as_mut_ptr();
    unsafe {
        (*event).header = header;
        (*event).source = [0u8; MAX_PATH_LEN];
        (*event).source_len = 0;
        (*event).target = [0u8; MAX_PATH_LEN];
        (*event).filesystem_type = [0u8; 32];
        (*event).filesystem_type_len = 0;
        (*event).is_umount = 1;
        (*event)._padding = [0u8; 2];

        let target_ptr: u64 = ctx.read_at(SYS_ENTER_ARG0_OFFSET).map_err(|_| -1i64)?;
        (*event).target_len = read_user_path_into(target_ptr, &mut (*event).target);
    }

    entry.submit(0);
    Ok(0)
}