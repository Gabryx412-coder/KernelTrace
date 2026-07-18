//! Lettura asincrona del ring buffer BPF, ponte tra il kernel e la
//! pipeline eventi userspace.

use aya::maps::{Map, RingBuf};
use bytes::Bytes;
use tokio::io::unix::AsyncFd;
use tracing::{debug, error};

use crate::error::{AgentError, AgentResult};

/// Estrae la mappa `EVENTS` (ring buffer) dall'oggetto eBPF caricato e la
/// prepara per la lettura asincrona.
pub fn take_ring_buffer(ebpf: &mut aya::Ebpf) -> AgentResult<RingBuf<&mut Map>> {
    let map = ebpf
        .map_mut("EVENTS")
        .ok_or(AgentError::RingBufMapNotFound("EVENTS"))?;

    RingBuf::try_from(map).map_err(|_| AgentError::RingBufMapNotFound("EVENTS"))
}

/// Task asincrono che legge continuamente il ring buffer e inoltra ogni
/// blocco di byte grezzo al canale della pipeline eventi.
///
/// Usa `AsyncFd` per integrarsi con il reactor di `tokio` senza polling
/// attivo: il task si sospende finché il kernel non segnala nuovi dati
/// disponibili, riducendo il consumo di CPU a riposo (requisito per
/// l'overhead complessivo `< 2%`).
pub async fn run_ringbuf_reader(
    mut ring_buf: RingBuf<&mut aya::maps::Map>,
    sender: tokio::sync::mpsc::Sender<Bytes>,
) -> AgentResult<()> {
    let async_fd = AsyncFd::new(ring_buf.as_raw_fd_wrapper())
        .map_err(AgentError::Io)?;

    loop {
        let mut guard = async_fd.readable().await.map_err(AgentError::Io)?;

        while let Some(item) = ring_buf.next() {
            let bytes = Bytes::copy_from_slice(&item);
            if sender.send(bytes).await.is_err() {
                error!("event pipeline channel closed, stopping ring buffer reader");
                return Err(AgentError::PipelineClosed);
            }
        }

        guard.clear_ready();
        debug!("ring buffer drained, waiting for next readiness notification");
    }
}