//! Entry point del binario `kerneltrace-agent`.
//!
//! Responsabilità: caricare la configurazione, inizializzare il logging,
//! caricare e attaccare i programmi eBPF, avviare la pipeline eventi, e
//! restare in esecuzione finché non viene ricevuto un segnale di terminazione.

use std::path::PathBuf;

use kerneltrace_agent::{
    config,
    events::{EventPipeline, NoopEnricher},
    loader,
    telemetry,
};
use tokio::signal;
use tracing::{error, info};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config_path: PathBuf = std::env::var("KERNELTRACE_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| config::default_config_path());

    let cfg = config::load_config(&config_path).unwrap_or_else(|err| {
        eprintln!(
            "warning: failed to load config from {}: {err}; falling back to defaults",
            config_path.display()
        );
        config::default_config()
    });

    let _telemetry_guard = telemetry::init_tracing(&cfg.logging);

    info!(config_path = %config_path.display(), "starting KernelTrace agent");

    loader::check_privileges()?;

    let mut ebpf = loader::load_ebpf_object().map_err(|err| {
        error!(error = %err, "failed to load eBPF object");
        err
    })?;

    if cfg.monitoring.process {
        loader::attach_process_probes(&mut ebpf)?;
    }

    let ring_buf = loader::take_ring_buffer(&mut ebpf)?;

    let pipeline = EventPipeline::new(cfg.agent.pipeline_capacity);
    let raw_sender = pipeline.sender();

    let (output_sender, mut output_receiver) = tokio::sync::mpsc::channel(cfg.agent.pipeline_capacity);

    // Task 1: legge il ring buffer BPF e inoltra i byte grezzi alla pipeline.
    let reader_handle = tokio::spawn(async move {
        if let Err(err) = loader::run_ringbuf_reader(ring_buf, raw_sender).await {
            error!(error = %err, "ring buffer reader task terminated");
        }
    });

    // Task 2: normalizza, arricchisce e inoltra gli eventi verso l'output
    // (in questa parte, un semplice stampa via tracing; il rules engine e
    // gli output sink veri e propri arrivano nelle Parti 10-11).
    let pipeline_handle = tokio::spawn(async move {
        pipeline
            .run(vec![Box::new(NoopEnricher)], output_sender)
            .await;
    });

    let consumer_handle = tokio::spawn(async move {
        while let Some(event) = output_receiver.recv().await {
            match serde_json::to_string(&event) {
                Ok(json) => println!("{json}"),
                Err(err) => error!(error = %err, "failed to serialize event to JSON"),
            }
        }
    });

    info!("KernelTrace agent is running. Press Ctrl+C to stop.");

    signal::ctrl_c().await?;
    info!("shutdown signal received, stopping agent");

    reader_handle.abort();
    pipeline_handle.abort();
    consumer_handle.abort();

    Ok(())
}