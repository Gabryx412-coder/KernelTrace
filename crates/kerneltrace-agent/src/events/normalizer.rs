//! Conversione dei byte grezzi ricevuti dal ring buffer in eventi
//! normalizzati (`NormalizedEvent`).

use bytes::Bytes;
use chrono::Utc;
use kerneltrace_common::{
    EventHeader, EventType, ExecEvent, FileEvent, MmapEvent, MountEvent, NetworkEvent,
    PrivilegeChangeEvent, ProcessLifecycleEvent, PtraceEvent, SignalEvent,
};
use std::net::{Ipv4Addr, Ipv6Addr};
use uuid::Uuid;

use crate::error::{AgentError, AgentResult};

use super::types::{EventKind, EventPayload, NormalizedEvent, ProcessContext};

/// Interpreta un blocco di byte grezzo proveniente dal ring buffer come uno
/// degli eventi definiti in `kerneltrace-common::events`, in base al campo
/// `event_type` presente nell'header comune.
pub fn normalize(raw: &Bytes) -> AgentResult<NormalizedEvent> {
    if raw.len() < EventHeader::SIZE {
        return Err(AgentError::EventParse(
            kerneltrace_common::CommonError::UnexpectedBufferSize {
                expected: EventHeader::SIZE,
                actual: raw.len(),
            },
        ));
    }

    let event_type = u32::from_ne_bytes(
        raw[0..4].try_into().expect("slice length checked above"),
    );

    match event_type {
        t if t == EventType::Exec as u32 => normalize_exec(raw),
        t if t == EventType::ProcessLifecycle as u32 => normalize_process_lifecycle(raw),
        t if t == EventType::FileOpen as u32
            || t == EventType::FileChange as u32
            || t == EventType::FileDelete as u32
            || t == EventType::FileRename as u32 =>
        {
            normalize_file(raw, event_type)
        }
        t if t == EventType::Connect as u32 || t == EventType::AcceptBindListen as u32 => {
            normalize_network(raw, event_type)
        }
        t if t == EventType::Ptrace as u32 => normalize_ptrace(raw),
        t if t == EventType::Mmap as u32 => normalize_mmap(raw),
        t if t == EventType::Signal as u32 => normalize_signal(raw),
        t if t == EventType::Mount as u32 => normalize_mount(raw),
        t if t == EventType::PrivilegeChange as u32 => normalize_privilege_change(raw),
        other => Err(AgentError::EventParse(
            kerneltrace_common::CommonError::UnknownEventType(other),
        )),
    }
}

fn read_struct<T: Copy>(raw: &Bytes) -> AgentResult<T> {
    let expected = std::mem::size_of::<T>();
    if raw.len() < expected {
        return Err(AgentError::EventParse(
            kerneltrace_common::CommonError::UnexpectedBufferSize {
                expected,
                actual: raw.len(),
            },
        ));
    }
    let value = unsafe { std::ptr::read_unaligned(raw.as_ptr() as *const T) };
    Ok(value)
}

fn process_context_from_header(header: &EventHeader) -> ProcessContext {
    let comm_len = header
        .comm
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(header.comm.len());
    let comm = String::from_utf8_lossy(&header.comm[..comm_len]).into_owned();

    ProcessContext {
        pid: header.pid,
        tgid: header.tgid,
        ppid: header.ppid,
        uid: header.uid,
        gid: header.gid,
        comm,
        cgroup_id: header.cgroup_id,
        parent_comm: None,
    }
}

fn timestamp_from_ktime_ns(_ktime_ns: u64) -> chrono::DateTime<Utc> {
    Utc::now()
}

fn truncated_string(bytes: &[u8], len: u16) -> String {
    let len = (len as usize).min(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).into_owned()
}

fn kind_for_event_type(event_type: u32) -> EventKind {
    match event_type {
        t if t == EventType::FileOpen as u32 => EventKind::FileOpen,
        t if t == EventType::FileChange as u32 => EventKind::FileChange,
        t if t == EventType::FileDelete as u32 => EventKind::FileDelete,
        t if t == EventType::FileRename as u32 => EventKind::FileRename,
        t if t == EventType::Connect as u32 => EventKind::Connect,
        _ => EventKind::AcceptBindListen,
    }
}

fn normalize_exec(raw: &Bytes) -> AgentResult<NormalizedEvent> {
    let event: ExecEvent = read_struct(raw)?;

    let filename = truncated_string(&event.filename, event.filename_len);

    let mut args = Vec::with_capacity(event.argc as usize);
    for i in 0..(event.argc as usize).min(event.argv.len()) {
        args.push(truncated_string(&event.argv[i], event.argv_len[i]));
    }

    Ok(NormalizedEvent {
        id: Uuid::new_v4(),
        timestamp: timestamp_from_ktime_ns(event.header.timestamp_ns),
        event_kind: EventKind::Exec,
        process: process_context_from_header(&event.header),
        payload: EventPayload::Exec { filename, args },
        container: None,
        tags: Vec::new(),
    })
}

fn normalize_process_lifecycle(raw: &Bytes) -> AgentResult<NormalizedEvent> {
    let event: ProcessLifecycleEvent = read_struct(raw)?;

    let syscall = kerneltrace_common::SyscallId::try_from(event.syscall_id)
        .map(|s| s.name().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    Ok(NormalizedEvent {
        id: Uuid::new_v4(),
        timestamp: timestamp_from_ktime_ns(event.header.timestamp_ns),
        event_kind: EventKind::ProcessLifecycle,
        process: process_context_from_header(&event.header),
        payload: EventPayload::ProcessLifecycle {
            syscall,
            exit_code: if event.exit_code != 0 {
                Some(event.exit_code)
            } else {
                None
            },
            is_orphan: event.is_orphan != 0,
            is_zombie: event.is_zombie != 0,
        },
        container: None,
        tags: Vec::new(),
    })
}

fn normalize_file(raw: &Bytes, event_type: u32) -> AgentResult<NormalizedEvent> {
    let event: FileEvent = read_struct(raw)?;

    let path = truncated_string(&event.path, event.path_len);
    let new_path = if event.new_path_len > 0 {
        Some(truncated_string(&event.new_path, event.new_path_len))
    } else {
        None
    };

    Ok(NormalizedEvent {
        id: Uuid::new_v4(),
        timestamp: timestamp_from_ktime_ns(event.header.timestamp_ns),
        event_kind: kind_for_event_type(event_type),
        process: process_context_from_header(&event.header),
        payload: EventPayload::File {
            path,
            new_path,
            open_flags: event.open_flags,
            mode: if event.mode != 0 { Some(event.mode) } else { None },
            new_owner_uid: if event.new_owner_uid != u32::MAX {
                Some(event.new_owner_uid)
            } else {
                None
            },
            new_owner_gid: if event.new_owner_gid != u32::MAX {
                Some(event.new_owner_gid)
            } else {
                None
            },
        },
        container: None,
        tags: Vec::new(),
    })
}

fn format_ip(addr_family: u8, addr: &[u8; 16]) -> String {
    if addr_family == 4 {
        Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]).to_string()
    } else if addr_family == 6 {
        Ipv6Addr::from(*addr).to_string()
    } else {
        "0.0.0.0".to_string()
    }
}

fn normalize_network(raw: &Bytes, event_type: u32) -> AgentResult<NormalizedEvent> {
    let event: NetworkEvent = read_struct(raw)?;

    let syscall = kerneltrace_common::SyscallId::try_from(event.syscall_id)
        .map(|s| s.name().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    Ok(NormalizedEvent {
        id: Uuid::new_v4(),
        timestamp: timestamp_from_ktime_ns(event.header.timestamp_ns),
        event_kind: kind_for_event_type(event_type),
        process: process_context_from_header(&event.header),
        payload: EventPayload::Network {
            address_family: event.address_family,
            protocol: event.protocol,
            src_addr: format_ip(event.address_family, &event.src_addr),
            dst_addr: format_ip(event.address_family, &event.dst_addr),
            src_port: event.src_port,
            dst_port: event.dst_port,
            syscall,
        },
        container: None,
        tags: Vec::new(),
    })
}

fn normalize_ptrace(raw: &Bytes) -> AgentResult<NormalizedEvent> {
    let event: PtraceEvent = read_struct(raw)?;

    Ok(NormalizedEvent {
        id: Uuid::new_v4(),
        timestamp: timestamp_from_ktime_ns(event.header.timestamp_ns),
        event_kind: EventKind::Ptrace,
        process: process_context_from_header(&event.header),
        payload: EventPayload::Ptrace {
            request: event.request,
            target_pid: event.target_pid,
        },
        container: None,
        tags: Vec::new(),
    })
}

fn normalize_mmap(raw: &Bytes) -> AgentResult<NormalizedEvent> {
    let event: MmapEvent = read_struct(raw)?;

    Ok(NormalizedEvent {
        id: Uuid::new_v4(),
        timestamp: timestamp_from_ktime_ns(event.header.timestamp_ns),
        event_kind: EventKind::Mmap,
        process: process_context_from_header(&event.header),
        payload: EventPayload::Mmap {
            addr: event.addr,
            length: event.length,
            prot_flags: event.prot_flags,
            map_flags: event.map_flags,
        },
        container: None,
        tags: Vec::new(),
    })
}

fn normalize_signal(raw: &Bytes) -> AgentResult<NormalizedEvent> {
    let event: SignalEvent = read_struct(raw)?;

    Ok(NormalizedEvent {
        id: Uuid::new_v4(),
        timestamp: timestamp_from_ktime_ns(event.header.timestamp_ns),
        event_kind: EventKind::Signal,
        process: process_context_from_header(&event.header),
        payload: EventPayload::Signal {
            target_pid: event.target_pid,
            signal: event.signal,
        },
        container: None,
        tags: Vec::new(),
    })
}

fn normalize_mount(raw: &Bytes) -> AgentResult<NormalizedEvent> {
    let event: MountEvent = read_struct(raw)?;

    let source = if event.source_len > 0 {
        Some(truncated_string(&event.source, event.source_len))
    } else {
        None
    };
    let target = truncated_string(&event.target, event.target_len);
    let filesystem_type = if event.filesystem_type_len > 0 {
        Some(truncated_string(
            &event.filesystem_type,
            event.filesystem_type_len as u16,
        ))
    } else {
        None
    };

    Ok(NormalizedEvent {
        id: Uuid::new_v4(),
        timestamp: timestamp_from_ktime_ns(event.header.timestamp_ns),
        event_kind: EventKind::Mount,
        process: process_context_from_header(&event.header),
        payload: EventPayload::Mount {
            source,
            target,
            filesystem_type,
            is_umount: event.is_umount != 0,
        },
        container: None,
        tags: Vec::new(),
    })
}

fn normalize_privilege_change(raw: &Bytes) -> AgentResult<NormalizedEvent> {
    let event: PrivilegeChangeEvent = read_struct(raw)?;

    Ok(NormalizedEvent {
        id: Uuid::new_v4(),
        timestamp: timestamp_from_ktime_ns(event.header.timestamp_ns),
        event_kind: EventKind::PrivilegeChange,
        process: process_context_from_header(&event.header),
        payload: EventPayload::PrivilegeChange {
            old_uid: event.old_uid,
            new_uid: event.new_uid,
            old_gid: event.old_gid,
            new_gid: event.new_gid,
            escalated_to_root: event.escalated_to_root != 0,
        },
        container: None,
        tags: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kerneltrace_common::{EventHeader, EventType};

    fn dummy_header(event_type: EventType) -> EventHeader {
        EventHeader {
            event_type: event_type as u32,
            timestamp_ns: 123_456,
            pid: 100,
            tgid: 100,
            ppid: 1,
            uid: 0,
            gid: 0,
            cgroup_id: 0,
            comm: {
                let mut c = [0u8; 16];
                c[..4].copy_from_slice(b"bash");
                c
            },
        }
    }

    fn bytes_of<T: Copy>(value: &T) -> Bytes {
        let slice = unsafe {
            std::slice::from_raw_parts(value as *const T as *const u8, std::mem::size_of::<T>())
        };
        Bytes::copy_from_slice(slice)
    }

    #[test]
    fn normalizes_process_lifecycle_event() {
        let event = ProcessLifecycleEvent {
            header: dummy_header(EventType::ProcessLifecycle),
            syscall_id: kerneltrace_common::SyscallId::Clone as u32,
            exit_code: 0,
            is_orphan: 0,
            is_zombie: 0,
            _padding: [0u8; 6],
        };

        let normalized = normalize(&bytes_of(&event)).expect("should normalize");
        assert_eq!(normalized.event_kind, EventKind::ProcessLifecycle);
    }

    #[test]
    fn normalizes_signal_event() {
        let event = SignalEvent {
            header: dummy_header(EventType::Signal),
            target_pid: 42,
            signal: 9,
        };

        let normalized = normalize(&bytes_of(&event)).expect("should normalize");
        assert_eq!(normalized.event_kind, EventKind::Signal);
        match normalized.payload {
            EventPayload::Signal { target_pid, signal } => {
                assert_eq!(target_pid, 42);
                assert_eq!(signal, 9);
            }
            _ => panic!("unexpected payload variant"),
        }
    }

    #[test]
    fn normalizes_privilege_change_event_flags_escalation() {
        let event = PrivilegeChangeEvent {
            header: dummy_header(EventType::PrivilegeChange),
            old_uid: 1000,
            new_uid: 0,
            old_gid: 1000,
            new_gid: 1000,
            escalated_to_root: 1,
            _padding: [0u8; 7],
        };

        let normalized = normalize(&bytes_of(&event)).expect("should normalize");
        match normalized.payload {
            EventPayload::PrivilegeChange {
                escalated_to_root, ..
            } => assert!(escalated_to_root),
            _ => panic!("unexpected payload variant"),
        }
    }

    #[test]
    fn format_ip_handles_ipv4() {
        let mut addr = [0u8; 16];
        addr[0..4].copy_from_slice(&[192, 168, 1, 10]);
        assert_eq!(format_ip(4, &addr), "192.168.1.10");
    }

    #[test]
    fn rejects_buffer_too_small() {
        let raw = Bytes::from_static(&[0u8; 2]);
        assert!(normalize(&raw).is_err());
    }

    #[test]
    fn rejects_unknown_event_type() {
        let mut bytes = vec![0u8; EventHeader::SIZE];
        bytes[0..4].copy_from_slice(&9999u32.to_ne_bytes());
        assert!(normalize(&Bytes::from(bytes)).is_err());
    }
}