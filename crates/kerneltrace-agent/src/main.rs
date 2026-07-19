//! Entry point del binario `kerneltrace-agent`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use kerneltrace_agent::{
    config::{self, OutputSinkKind},
    container::{ContainerResolver, ContainerResolverConfig},
    detection::{load_all_rules, DetectionEngine},
    events::{Enricher, EventPipeline},
    fim::{Baseline, FimWatcher},
    loader,
    network::{
        BeaconingDetector, BeaconingTracker, ConnectionTracker, ConnectionTrackerEnricher,
        ReverseShellDetector,
    },
    output::{FileSink, JsonSink, OutputManager, Sink, StdoutSink},
    process::{OrphanZombieScanner, PrivilegeEscalationEnricher, ProcessTree, ProcessTreeEnricher},
    response::{LoggingOnlyResponseAction, ResponseDispatcher},
    telemetry,
};
use tokio::signal;
use tracing::{error, info, warn};

fn build_sinks(cfg: &kerneltrace_agent::config::Config) -> Vec<Box<dyn Sink>> {
    let mut sinks: Vec<Box<dyn Sink>> = Vec::new();

    for kind in &cfg.output.sinks {
        match kind {
            OutputSinkKind::Stdout => sinks.push(Box::new(StdoutSink::new())),
            OutputSinkKind::File => match &cfg.output.file_path {
                Some(path) => match FileSink::new(path) {
                    Ok(sink) => sinks.push(Box::new(sink)),
                    Err(err) => warn!(error = %err, path = %path.display(), "failed to initialize file sink, skipping"),
                },
                None => warn!("file sink configured without output.file_path, skipping"),
            },
            OutputSinkKind::Json => match &cfg.output.file_path {
                Some(path) => match JsonSink::new(path) {
                    Ok(sink) => sinks.push(Box::new(sink)),
                    Err(err) => warn!(error = %err, path = %path.display(), "failed to initialize json sink, skipping"),
                },
                None => warn!("json sink configured without output.file_path, skipping"),
            },
        }
    }

    sinks
}

/// Costruisce il dispatcher di risposta automatica se abilitato in
/// configurazione. In questa fase del progetto sono disponibili solo
/// azioni "logging-only" (nessun effetto reale): predispone il pattern di
/// wiring per le azioni concrete (kill/blocco IP/quarantena) pianificate
/// in ROADMAP.md, senza introdurle prematuramente.
fn build_response_dispatcher(
    cfg: &kerneltrace_agent::config::Config,
) -> Option<ResponseDispatcher> {
    if !cfg.response.enabled {
        return None;
    }

    let actions: Vec<Box<dyn kerneltrace_agent::response::ResponseAction>> = vec![Box::new(
        LoggingOnlyResponseAction::new("log-critical-detections", "rule:builtin-shell-from-webserver"),
    )];

    Some(ResponseDispatcher::new(actions, cfg.response.dry_run))
}

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

    let rules = load_all_rules(&cfg.rules.directories, cfg.rules.strict_parsing).unwrap_or_else(|err| {
        warn!(error = %err, "failed to load detection rules, starting with an empty rule set");
        Vec::new()
    });
    let detection_engine = DetectionEngine::new(rules);
    let sequence_pruner_handle = detection_engine.spawn_sequence_pruner();
    enrichers.push(Box::new(detection_engine));

    let output_manager = Arc::new(OutputManager::new(build_sinks(&cfg)));
    info!(sinks = output_manager.sink_count(), "output sinks initialized");

    let response_dispatcher = build_response_dispatcher(&cfg).map(Arc::new);
    if let Some(dispatcher) = &response_dispatcher {
        info!(
            actions = dispatcher.action_count(),
            dry_run = dispatcher.is_dry_run(),
            "response dispatcher initialized"
        );
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

    let consumer_output_manager = Arc::clone(&output_manager);
    let consumer_response_dispatcher = response_dispatcher.clone();
    let consumer_handle = tokio::spawn(async move {
        while let Some(event) = output_receiver.recv().await {
            consumer_output_manager.dispatch(&event);

            if let Some(dispatcher) = &consumer_response_dispatcher {
                let _ = dispatcher.dispatch(&event);
            }
        }
    });

    info!("KernelTrace agent is running. Press Ctrl+C to stop.");

    signal::ctrl_c().await?;
    info!("shutdown signal received, stopping agent");

    reader_handle.abort();
    pipeline_handle.abort();
    scanner_handle.abort();
    sequence_pruner_handle.abort();
    consumer_handle.abort();

    output_manager.flush_all();

    Ok(())
}