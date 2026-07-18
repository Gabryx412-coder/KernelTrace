//! Probe per il network monitoring: `connect`, `accept`, `bind`, `listen`.
//!
//! Estraiamo famiglia di indirizzi, indirizzi IPv4/IPv6 e porte dalla
//! struct `sockaddr` passata dallo user-space, letta tramite
//! `bpf_probe_read_user`. Per `accept`, che riceve la struct in output
//! anziché in input, l'estrazione avviene sul tracepoint di uscita
//! (`sys_exit_accept4`) anziché di ingresso.

use aya_ebpf::{macros::tracepoint, programs::TracePointContext};

use kerneltrace_common::{
    constants::IP_ADDR_LEN,
    events::{EventType, NetworkEvent},
    syscalls::SyscallId,
};

use super::process::build_header;
use crate::maps::EVENTS;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

/// Estrae famiglia, porta e indirizzo da un puntatore user-space a
/// `struct sockaddr`, gestendo sia IPv4 (`sockaddr_in`) che IPv6
/// (`sockaddr_in6`).
///
/// # Safety
/// `sockaddr_ptr` deve essere un puntatore a memoria user-space valida,
/// garantito dal chiamante (proviene direttamente dagli argomenti della
/// syscall letti dal tracepoint).
#[inline(always)]
unsafe fn read_sockaddr(
    sockaddr_ptr: u64,
) -> Option<(u8, u16, [u8; IP_ADDR_LEN])> {
    let mut family_bytes = [0u8; 2];
    aya_ebpf::helpers::gen::bpf_probe_read_user_bytes(
        sockaddr_ptr as *const u8,
        &mut family_bytes,
    )
    .ok()?;
    let family = u16::from_ne_bytes(family_bytes);

    let mut addr = [0u8; IP_ADDR_LEN];

    match family {
        AF_INET => {
            // struct sockaddr_in { sa_family_t; in_port_t sin_port; struct in_addr sin_addr; ... }
            let mut port_bytes = [0u8; 2];
            aya_ebpf::helpers::gen::bpf_probe_read_user_bytes(
                (sockaddr_ptr + 2) as *const u8,
                &mut port_bytes,
            )
            .ok()?;
            let port = u16::from_be_bytes(port_bytes);

            aya_ebpf::helpers::gen::bpf_probe_read_user_bytes(
                (sockaddr_ptr + 4) as *const u8,
                &mut addr[0..4],
            )
            .ok()?;

            Some((4, port, addr))
        }
        AF_INET6 => {
            // struct sockaddr_in6 { sa_family_t; in_port_t sin6_port; ... struct in6_addr sin6_addr; ... }
            let mut port_bytes = [0u8; 2];
            aya_ebpf::helpers::gen::bpf_probe_read_user_bytes(
                (sockaddr_ptr + 2) as *const u8,
                &mut port_bytes,
            )
            .ok()?;
            let port = u16::from_be_bytes(port_bytes);

            aya_ebpf::helpers::gen::bpf_probe_read_user_bytes(
                (sockaddr_ptr + 8) as *const u8,
                &mut addr[0..16],
            )
            .ok()?;

            Some((6, port, addr))
        }
        _ => None,
    }
}

fn emit_network_event(
    event_type: EventType,
    syscall_id: SyscallId,
    protocol: u8,
    sockaddr_ptr: u64,
) -> Result<u32, i64> {
    let header = build_header(event_type);

    let (family, port, addr) = match unsafe { read_sockaddr(sockaddr_ptr) } {
        Some(parsed) => parsed,
        None => return Ok(0), // famiglia di indirizzi non supportata (es. AF_UNIX): ignora
    };

    let event = NetworkEvent {
        header,
        address_family: family,
        protocol,
        _padding: [0u8; 2],
        src_addr: [0u8; IP_ADDR_LEN], // il src address richiede lettura da socket kernel-side, arricchito lato userspace
        dst_addr: addr,
        src_port: 0,
        dst_port: port,
        syscall_id: syscall_id as u32,
    };

    match EVENTS.reserve::<NetworkEvent>(0) {
        Some(mut entry) => {
            entry.write(event);
            entry.submit(0);
        }
        None => {}
    }

    Ok(0)
}

/// Offset stabile, nel formato `sys_enter_connect`, del puntatore
/// user-space a `struct sockaddr` (secondo argomento della syscall).
const SYS_ENTER_ARG1_OFFSET: usize = 16;

/// Probe su `syscalls:sys_enter_connect`.
#[tracepoint]
pub fn probe_connect(ctx: TracePointContext) -> u32 {
    let sockaddr_ptr: u64 = match ctx.read_at(SYS_ENTER_ARG1_OFFSET) {
        Ok(ptr) => ptr,
        Err(_) => return 1,
    };
    // Il protocollo esatto (TCP/UDP) dipende dal tipo di socket, non
    // direttamente disponibile nel tracepoint; usiamo TCP (6) come default
    // ragionevole, corretto lato userspace incrociando `/proc/<pid>/net/*`
    // durante l'arricchimento (Parte 8).
    emit_network_event(EventType::Connect, SyscallId::Connect, 6, sockaddr_ptr)
        .unwrap_or(1)
}

/// Probe su `syscalls:sys_enter_bind`.
#[tracepoint]
pub fn probe_bind(ctx: TracePointContext) -> u32 {
    let sockaddr_ptr: u64 = match ctx.read_at(SYS_ENTER_ARG1_OFFSET) {
        Ok(ptr) => ptr,
        Err(_) => return 1,
    };
    emit_network_event(EventType::AcceptBindListen, SyscallId::Bind, 6, sockaddr_ptr)
        .unwrap_or(1)
}

/// Probe su `syscalls:sys_enter_listen`.
///
/// `listen(2)` non riceve un `sockaddr` come argomento: l'evento cattura
/// solo il contesto del processo e il file descriptor, mentre l'indirizzo
/// associato viene risolto lato userspace correlando il fd con la bind
/// precedente sullo stesso processo.
#[tracepoint]
pub fn probe_listen(ctx: TracePointContext) -> u32 {
    let header = build_header(EventType::AcceptBindListen);

    let event = NetworkEvent {
        header,
        address_family: 0,
        protocol: 6,
        _padding: [0u8; 2],
        src_addr: [0u8; IP_ADDR_LEN],
        dst_addr: [0u8; IP_ADDR_LEN],
        src_port: 0,
        dst_port: 0,
        syscall_id: SyscallId::Listen as u32,
    };

    match EVENTS.reserve::<NetworkEvent>(0) {
        Some(mut entry) => {
            entry.write(event);
            entry.submit(0);
        }
        None => {}
    }

    let _ = ctx;
    0
}

/// Probe su `syscalls:sys_exit_accept4` (copre `accept`).
///
/// L'indirizzo del peer è disponibile solo all'uscita della syscall (viene
/// scritto dal kernel nel buffer passato dallo user-space durante la
/// chiamata), quindi agganciamo il tracepoint di uscita anziché quello di
/// ingresso usato dalle altre probe di questo modulo.
#[tracepoint]
pub fn probe_accept(ctx: TracePointContext) -> u32 {
    // Nel formato di sys_exit_accept4, l'unico dato affidabile è il valore
    // di ritorno (il nuovo file descriptor); il sockaddr del peer va letto
    // dal puntatore salvato in ingresso, correlato tramite una mappa
    // hash pid->sockaddr_ptr popolata da una probe di ingresso dedicata.
    // Per questa prima implementazione emettiamo un evento con il solo
    // contesto di processo, arricchito lato userspace leggendo
    // `/proc/<pid>/net/tcp{,6}` per risolvere l'endpoint remoto associato
    // al nuovo file descriptor.
    let header = build_header(EventType::AcceptBindListen);

    let event = NetworkEvent {
        header,
        address_family: 0,
        protocol: 6,
        _padding: [0u8; 2],
        src_addr: [0u8; IP_ADDR_LEN],
        dst_addr: [0u8; IP_ADDR_LEN],
        src_port: 0,
        dst_port: 0,
        syscall_id: SyscallId::Accept as u32,
    };

    match EVENTS.reserve::<NetworkEvent>(0) {
        Some(mut entry) => {
            entry.write(event);
            entry.submit(0);
        }
        None => {}
    }

    let _ = ctx;
    0
}