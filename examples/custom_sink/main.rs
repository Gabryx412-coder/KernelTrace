//! Esempio: implementazione di un `Sink` custom che inoltra ogni evento
//! come richiesta HTTP POST verso un webhook, dimostrando come estendere
//! gli output di KernelTrace senza modificare il crate `kerneltrace-agent`.
//!
//! Questo pattern è il percorso naturale per costruire in futuro sink
//! verso Elastic, Splunk HEC, o qualsiasi altro sistema che accetti eventi
//! via HTTP, mantenendo la stessa interfaccia `Sink` usata dai sink
//! built-in (stdout/file/json).
//!
//! Esecuzione:
//! ```bash
//! # Avvia un endpoint di test locale, ad es. con `webhook.site` o netcat:
//! nc -lk 8080
//!
//! cd examples/custom_sink
//! sudo cargo run --release -- http://localhost:8080/events
//! ```

use kerneltrace_agent::error::{AgentError, AgentResult};
use kerneltrace_agent::events::{Enricher, EventPipeline, NormalizedEvent};
use kerneltrace_agent::loader;
use kerneltrace_agent::output::{OutputManager, Sink};
use kerneltrace_agent::process::{ProcessTree, ProcessTreeEnricher};
use std::sync::Arc;
use tracing::{error, info, warn};

/// Sink custom che inoltra ogni evento come richiesta HTTP POST verso un
/// endpoint webhook configurato.
///
/// Implementa lo stesso trait `Sink` usato dai sink built-in
/// (`StdoutSink`, `FileSink`, `JsonSink`), dimostrando che l'estensibilità
/// degli output non richiede modifiche al crate `kerneltrace-agent`.
struct WebhookSink {
    endpoint: String,
    agent: ureq::Agent,
}

impl WebhookSink {
    fn new(endpoint: String) -> Self {
        Self {
            endpoint,
            // Timeout breve deliberato: un webhook lento non deve
            // bloccare a lungo il thread che processa gli eventi.
            agent: ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_secs(2))
                .build(),
        }
    }
}

impl Sink for WebhookSink {
    fn name(&self) -> &'static str {
        "webhook"
    }

    fn write_event(&self, event: &NormalizedEvent) -> AgentResult<()> {
        self.agent
            .post(&self.endpoint)
            .send_json(event)
            .map(|_| ())
            .map_err(|err| {
                AgentError::ConfigValidation(format!("webhook POST failed: {err}"))
            })
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let endpoint = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "http://localhost:8080/events".to_string());

    info!(endpoint = %endpoint, "avvio con sink webhook custom");

    let mut ebpf = loader::load_ebpf_object()?;
    loader::attach_process_probes(&mut ebpf)?;

    let ring_buf = loader::take_ring_buffer(&mut ebpf)?;

    let pipeline = EventPipeline::new(4096);
    let raw_sender = pipeline.sender();
    let (output_sender, mut output_receiver) = tokio::sync::mpsc::channel(4096);

    let process_tree = Arc::new(ProcessTree::new());
    let enrichers: Vec<Box<dyn Enricher>> =
        vec![Box::new(ProcessTreeEnricher::new(Arc::clone(&process_tree)))];

    // L'OutputManager qui è configurato con un solo sink custom, ma in
    // un caso reale potresti combinarlo con StdoutSink/JsonSink per avere
    // sia l'inoltro verso il webhook sia una copia locale su file.
    let output_manager = OutputManager::new(vec![Box::new(WebhookSink::new(endpoint))]);

    let reader_handle = tokio::spawn(async move {
        if let Err(err) = loader::run_ringbuf_reader(ring_buf, raw_sender).await {
            error!(error = %err, "ring buffer reader terminated");
        }
    });

    let pipeline_handle = tokio::spawn(async move {
        pipeline.run(enrichers, output_sender).await;
    });

    let consumer_handle = tokio::spawn(async move {
        while let Some(event) = output_receiver.recv().await {
            output_manager.dispatch(&event);
        }
    });

    info!("In ascolto. Premi Ctrl+C per uscire.");
    tokio::signal::ctrl_c().await?;

    reader_handle.abort();
    pipeline_handle.abort();
    consumer_handle.abort();

    warn!("Arresto completato.");
    Ok(())
}