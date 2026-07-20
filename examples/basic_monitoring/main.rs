//! Esempio minimo: carica i programmi eBPF di process monitoring, legge
//! il ring buffer, normalizza gli eventi e li stampa su stdout — senza
//! rules engine, enricher aggiuntivi, né output sink configurabili.
//!
//! Utile come punto di partenza per capire il flusso dati minimo prima di
//! esplorare la pipeline completa usata da `kerneltrace-agent::main`.
//!
//! Esecuzione (richiede privilegi eBPF):
//! ```bash
//! cd examples/basic_monitoring
//! sudo cargo run --release
//! ```

use kerneltrace_agent::events::normalize;
use kerneltrace_agent::loader;
use tracing::{error, info};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    info!("Caricamento programmi eBPF di process monitoring...");

    let mut ebpf = loader::load_ebpf_object()?;
    loader::attach_process_probes(&mut ebpf)?;

    let ring_buf = loader::take_ring_buffer(&mut ebpf)?;

    // A differenza dell'agente completo, qui non usiamo l'EventPipeline
    // con canale asincrono: leggiamo e stampiamo direttamente in un unico
    // task per mantenere l'esempio il più semplice possibile da seguire.
    let (raw_sender, mut raw_receiver) = tokio::sync::mpsc::channel(1024);

    let reader_handle = tokio::spawn(async move {
        if let Err(err) = loader::run_ringbuf_reader(ring_buf, raw_sender).await {
            error!(error = %err, "ring buffer reader terminated");
        }
    });

    info!("In ascolto di eventi di processo. Premi Ctrl+C per uscire.");
    info!("Prova ad eseguire un comando in un altro terminale, es: `ls`");

    let print_handle = tokio::spawn(async move {
        while let Some(raw) = raw_receiver.recv().await {
            match normalize(&raw) {
                Ok(event) => {
                    println!(
                        "[{}] {:?} pid={} comm={}",
                        event.timestamp.format("%H:%M:%S%.3f"),
                        event.event_kind,
                        event.process.pid,
                        event.process.comm
                    );
                }
                Err(err) => {
                    error!(error = %err, "failed to normalize event, skipping");
                }
            }
        }
    });

    tokio::signal::ctrl_c().await?;
    info!("Arresto in corso...");

    reader_handle.abort();
    print_handle.abort();

    Ok(())
}