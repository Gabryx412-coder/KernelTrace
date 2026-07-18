//! Probe per il file monitoring: `open`, `openat`, `unlink`, `rename`,
//! `chmod`, `chown`.
//!
//! Usiamo i tracepoint `syscalls:sys_enter_<nome>`, che espongono gli
//! argomenti della syscall in un formato stabile e documentato
//! (`/sys/kernel/debug/tracing/events/syscalls/sys_enter_*/format`),
//! evitando la fragilità dei kprobe sui nomi delle funzioni interne del
//! kernel VFS.

use aya_ebpf::{macros::tracepoint, programs::TracePointContext};

use kerneltrace_common::{
    constants::MAX_PATH_LEN,
    events::{EventHeader, EventType, FileEvent},
};

use super::process::build_header;
use crate::maps::EVENTS;

/// Legge una stringa puntata da user-space (path di un file) in un buffer
/// a dimensione fissa, troncando a `MAX_PATH_LEN` byte.
///
/// # Safety
/// `dest` deve puntare a un buffer di almeno `MAX_PATH_LEN` byte validi.
#[inline(always)]
unsafe fn read_user_path(user_ptr: u64, dest: &mut [u8; MAX_PATH_LEN]) -> u16 {
    match aya_ebpf::helpers::gen::bpf_probe_read_user_str_bytes(
        user_ptr as *const u8,
        dest,
    ) {
        Ok(len) => len.min(MAX_PATH_LEN) as u16,
        Err(_) => 0,
    }
}

/// Offset stabile, nel formato del tracepoint `sys_enter_openat`, del
/// puntatore user-space al filename (secondo argomento della syscall,
/// dopo i 8 byte di preambolo comuni a tutti i tracepoint syscalls).
const SYS_ENTER_ARG1_OFFSET: usize = 16;

/// Probe su `syscalls:sys_enter_openat` (copre anche `open`, che sui
/// kernel moderni è implementato internamente come `openat` con `dfd =
/// AT_FDCWD`).
#[tracepoint]
pub fn probe_openat(ctx: TracePointContext) -> u32 {
    match try_probe_open(&ctx, false) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_probe_open(ctx: &TracePointContext, _is_open: bool) -> Result<u32, i64> {
    let header = build_header(EventType::FileOpen);

    let mut entry = match EVENTS.reserve::<FileEvent>(0) {
        Some(entry) => entry,
        None => return Ok(0),
    };

    let event = entry.as_mut_ptr();
    unsafe {
        (*event).header = header;
        (*event).path = [0u8; MAX_PATH_LEN];
        (*event).new_path = [0u8; MAX_PATH_LEN];
        (*event).new_path_len = 0;
        (*event).mode = 0;
        (*event).new_owner_uid = u32::MAX;
        (*event).new_owner_gid = u32::MAX;

        let filename_ptr: u64 = ctx.read_at(SYS_ENTER_ARG1_OFFSET).map_err(|_| -1i64)?;
        (*event).path_len = read_user_path(filename_ptr, &mut (*event).path);

        // Il secondo argomento di sys_enter_openat (offset +24) contiene i
        // flag O_* passati alla syscall.
        (*event).open_flags = ctx.read_at::<i32>(24).unwrap_or(0) as u32;
    }

    entry.submit(0);
    Ok(0)
}

/// Probe su `syscalls:sys_enter_unlinkat` (copre `unlink`).
#[tracepoint]
pub fn probe_unlink(ctx: TracePointContext) -> u32 {
    match try_probe_unlink(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_probe_unlink(ctx: &TracePointContext) -> Result<u32, i64> {
    let header = build_header(EventType::FileDelete);

    let mut entry = match EVENTS.reserve::<FileEvent>(0) {
        Some(entry) => entry,
        None => return Ok(0),
    };

    let event = entry.as_mut_ptr();
    unsafe {
        (*event).header = header;
        (*event).path = [0u8; MAX_PATH_LEN];
        (*event).new_path = [0u8; MAX_PATH_LEN];
        (*event).new_path_len = 0;
        (*event).open_flags = 0;
        (*event).mode = 0;
        (*event).new_owner_uid = u32::MAX;
        (*event).new_owner_gid = u32::MAX;

        let path_ptr: u64 = ctx.read_at(SYS_ENTER_ARG1_OFFSET).map_err(|_| -1i64)?;
        (*event).path_len = read_user_path(path_ptr, &mut (*event).path);
    }

    entry.submit(0);
    Ok(0)
}

/// Probe su `syscalls:sys_enter_renameat2` (copre `rename`).
#[tracepoint]
pub fn probe_rename(ctx: TracePointContext) -> u32 {
    match try_probe_rename(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_probe_rename(ctx: &TracePointContext) -> Result<u32, i64> {
    let header = build_header(EventType::FileRename);

    let mut entry = match EVENTS.reserve::<FileEvent>(0) {
        Some(entry) => entry,
        None => return Ok(0),
    };

    let event = entry.as_mut_ptr();
    unsafe {
        (*event).header = header;
        (*event).path = [0u8; MAX_PATH_LEN];
        (*event).new_path = [0u8; MAX_PATH_LEN];
        (*event).open_flags = 0;
        (*event).mode = 0;
        (*event).new_owner_uid = u32::MAX;
        (*event).new_owner_gid = u32::MAX;

        // sys_enter_renameat2: arg0 = olddfd, arg1 = oldname (offset 16),
        // arg2 = newdfd, arg3 = newname (offset 32).
        let old_ptr: u64 = ctx.read_at(SYS_ENTER_ARG1_OFFSET).map_err(|_| -1i64)?;
        (*event).path_len = read_user_path(old_ptr, &mut (*event).path);

        let new_ptr: u64 = ctx.read_at(32).map_err(|_| -1i64)?;
        (*event).new_path_len = read_user_path(new_ptr, &mut (*event).new_path);
    }

    entry.submit(0);
    Ok(0)
}

/// Probe su `syscalls:sys_enter_fchmodat` (copre `chmod`).
#[tracepoint]
pub fn probe_chmod(ctx: TracePointContext) -> u32 {
    match try_probe_chmod(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_probe_chmod(ctx: &TracePointContext) -> Result<u32, i64> {
    let mut header = build_header(EventType::FileChange);
    header.event_type = EventType::FileChange as u32;

    let mut entry = match EVENTS.reserve::<FileEvent>(0) {
        Some(entry) => entry,
        None => return Ok(0),
    };

    let event = entry.as_mut_ptr();
    unsafe {
        (*event).header = header;
        (*event).path = [0u8; MAX_PATH_LEN];
        (*event).new_path = [0u8; MAX_PATH_LEN];
        (*event).new_path_len = 0;
        (*event).open_flags = 0;
        (*event).new_owner_uid = u32::MAX;
        (*event).new_owner_gid = u32::MAX;

        let path_ptr: u64 = ctx.read_at(SYS_ENTER_ARG1_OFFSET).map_err(|_| -1i64)?;
        (*event).path_len = read_user_path(path_ptr, &mut (*event).path);

        // arg1 = mode (offset 24 per fchmodat: dfd, filename, mode, flags).
        (*event).mode = ctx.read_at::<u32>(24).unwrap_or(0);
    }

    entry.submit(0);
    Ok(0)
}

/// Probe su `syscalls:sys_enter_fchownat` (copre `chown`).
#[tracepoint]
pub fn probe_chown(ctx: TracePointContext) -> u32 {
    match try_probe_chown(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_probe_chown(ctx: &TracePointContext) -> Result<u32, i64> {
    let header = build_header(EventType::FileChange);

    let mut entry = match EVENTS.reserve::<FileEvent>(0) {
        Some(entry) => entry,
        None => return Ok(0),
    };

    let event = entry.as_mut_ptr();
    unsafe {
        (*event).header = header;
        (*event).path = [0u8; MAX_PATH_LEN];
        (*event).new_path = [0u8; MAX_PATH_LEN];
        (*event).new_path_len = 0;
        (*event).open_flags = 0;
        (*event).mode = 0;

        let path_ptr: u64 = ctx.read_at(SYS_ENTER_ARG1_OFFSET).map_err(|_| -1i64)?;
        (*event).path_len = read_user_path(path_ptr, &mut (*event).path);

        // sys_enter_fchownat: arg0 dfd, arg1 filename, arg2 uid (offset 24), arg3 gid (offset 32).
        (*event).new_owner_uid = ctx.read_at::<i32>(24).unwrap_or(-1) as u32;
        (*event).new_owner_gid = ctx.read_at::<i32>(32).unwrap_or(-1) as u32;
    }

    entry.submit(0);
    Ok(0)
}