//! Entry point del binario `kerneltrace-agent`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use kerneltrace_agent::{
    config,
    container::{ContainerResolver, ContainerResolverConfig},
    events::{Enricher, EventPipeline},
    fim::{Baseline, FimWatcher},
    loader,
    network::{
        BeaconingDetector, BeaconingTracker, ConnectionTracker, ConnectionTrackerEnricher,
        ReverseShellDetector,
    },
    process::{OrphanZombieScanner, PrivilegeEscalationEnricher, ProcessTree, ProcessTreeEnricher},
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
    if cfg.monitoring.file_integrity {
        loader::attach_file_probes(&mut ebpf)?;
    }
    if cfg.monitoring.network {
        loader::attach_network_probes(&mut ebpf)?;
    }

    let ring_buf = loader::take_ring_buffer(&mut ebpf)?;

    let pipeline = EventPipeline::new(cfg.agent.pipeline_capacity);
    let raw_sender = pipeline.sender();

    let (output_sender, mut output_receiver) =
        tokio::sync::mpsc::channel(cfg.agent.pipeline_capacity);

    let process_tree = Arc::new(ProcessTree::new());

    // Il ContainerResolver viene per primo nella catena: il contesto
    // container che popola è potenzialmente utile anche ai detector
    // successivi (es. regole differenziate per processi containerizzati
    // nel rules engine, Parte 10).
    let mut enrichers: Vec<Box<dyn Enricher>> = vec![Box::new(ContainerResolver::new(
        ContainerResolverConfig {
            docker: cfg.container.docker,
            podman: cfg.container.podman,
            kubernetes: cfg.container.kubernetes,
        },
    ))];

    enrichers.push(Box::new(ProcessTreeEnricher::new(Arc::clone(&process_tree))));
    enrichers.push(Box::new(PrivilegeEscalationEnricher::new()));

    if cfg.monitoring.file_integrity {
        let baseline = Arc::new(Baseline::new(cfg.monitoring.fim_hash_algorithm));
        let fim_watcher =
            FimWatcher::new(Arc::clone(&baseline), cfg.monitoring.fim_watch_paths.clone());

        let files_registered = fim_watcher.build_initial_baseline();
        info!(files = files_registered, "FIM initial baseline built");

        enrichers.push(Box::new(fim_watcher));
    }

    if cfg.monitoring.network {
        let connection_tracker = Arc::new(ConnectionTracker::new());
        let beaconing_tracker = Arc::new(BeaconingTracker::new());

        enrichers.push(Box::new(ConnectionTrackerEnricher::new(Arc::clone(
            &connection_tracker,
        ))));
        enrichers.push(Box::new(ReverseShellDetector));
        enrichers.push(Box::new(BeaconingDetector::new(Arc::clone(
            &beaconing_tracker,
        ))));
    }

    let reader_handle = tokio::spawn(async move {
        if let Err(err) = loader::run_ringbuf_reader(ring_buf, raw_sender).await {
            error!(error = %err, "ring buffer reader task terminated");
        }
    });

    let pipeline_handle = tokio::spawn(async move {
        pipeline.run(enrichers, output_sender).await;
    });

    let scanner = OrphanZombieScanner::new(Arc::clone(&process_tree), Duration::from_secs(5));
    let scanner_handle = tokio::spawn(scanner.run());

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
    scanner_handle.abort();
    consumer_handle.abort();

    Ok(())
}