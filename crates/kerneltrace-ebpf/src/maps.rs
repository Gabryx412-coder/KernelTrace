//! Definizione delle mappe BPF condivise tra le varie probe e lette
//! dall'agente userspace.

use aya_ebpf::{macros::map, maps::RingBuf};
use kerneltrace_common::constants::RING_BUFFER_SIZE_BYTES;

/// Ring buffer principale su cui tutte le probe scrivono gli eventi.
///
/// Un singolo ring buffer condiviso (anziché uno per tipo di evento)
/// semplifica l'ordinamento cronologico lato userspace: l'agente legge un
/// unico stream di byte e usa il campo `event_type` nell'header per il
/// dispatch, senza dover fondere più stream con lock o `select!` multipli.
#[map(name = "EVENTS")]
pub static EVENTS: RingBuf = RingBuf::with_byte_size(RING_BUFFER_SIZE_BYTES, 0);