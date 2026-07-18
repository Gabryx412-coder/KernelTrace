//! Conversione dei byte grezzi ricevuti dal ring buffer in eventi
//! normalizzati (`NormalizedEvent`).

use bytes::Bytes;
use chrono::{TimeZone, Utc};
use kerneltrace_common::{EventHeader, EventType, ExecEvent, ProcessLifecycleEvent};
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

    // Safety: la dimensione è stata verificata sopra, e le struct evento
    // sono `#[repr(C)]` con layout identico a quello scritto dal programma
    // eBPF nello stesso ordine di byte (target `bpfel`/host entrambi
    // little-endian su x86_64/aarch64).
    let event_type = u32::from_ne_bytes(
        raw[0..4]
            .try_into()
            .expect("slice length checked above"),
    );

    match event_type {
        t if t == EventType::Exec as u32 => normalize_exec(raw),
        t if t == EventType::ProcessLifecycle as u32 => normalize_process_lifecycle(raw),
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
    // Safety: dimensione verificata sopra; T è sempre una delle struct
    // `#[repr(C)]` di kerneltrace_common::events, senza puntatori interni.
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
    }
}

fn timestamp_from_ktime_ns(_ktime_ns: u64) -> chrono::DateTime<Utc> {
    // `bpf_ktime_get_ns` restituisce il tempo trascorso da boot, non un
    // timestamp Unix; la conversione a wall-clock richiede di conoscere
    // l'istante di boot del sistema. Per semplicità in questa fase usiamo
    // il tempo di ricezione lato userspace; una conversione precisa basata
    // su `/proc/stat` (btime) può essere aggiunta come raffinamento futuro
    // senza cambiare il formato degli eventi a valle.
    Utc::now()
}

fn normalize_exec(raw: &Bytes) -> AgentResult<NormalizedEvent> {
    let event: ExecEvent = read_struct(raw)?;

    let filename_len = event.filename_len as usize;
    let filename = String::from_utf8_lossy(&event.filename[..filename_len]).into_owned();

    let mut args = Vec::with_capacity(event.argc as usize);
    for i in 0..(event.argc as usize).min(event.argv.len()) {
        let len = event.argv_len[i] as usize;
        args.push(String::from_utf8_lossy(&event.argv[i][..len]).into_owned());
    }

    Ok(NormalizedEvent {
        id: Uuid::new_v4(),
        timestamp: timestamp_from_ktime_ns(event.header.timestamp_ns),
        event_kind: EventKind::Exec,
        process: process_context_from_header(&event.header),
        payload: EventPayload::Exec { filename, args },
        container: None,
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

        let bytes = unsafe {
            std::slice::from_raw_parts(
                &event as *const _ as *const u8,
                std::mem::size_of::<ProcessLifecycleEvent>(),
            )
        };
        let raw = Bytes::copy_from_slice(bytes);

        let normalized = normalize(&raw).expect("should normalize");
        assert_eq!(normalized.event_kind, EventKind::ProcessLifecycle);
        assert_eq!(normalized.process.comm, "bash");
    }

    #[test]
    fn rejects_buffer_too_small() {
        let raw = Bytes::from_static(&[0u8; 2]);
        let result = normalize(&raw);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_unknown_event_type() {
        let mut bytes = vec![0u8; EventHeader::SIZE];
        bytes[0..4].copy_from_slice(&9999u32.to_ne_bytes());
        let raw = Bytes::from(bytes);

        let result = normalize(&raw);
        assert!(result.is_err());
    }
}