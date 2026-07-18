//! Inizializzazione di `tracing-subscriber` in base alla configurazione
//! dell'agente (livello, formato, output su file rotante).

use std::path::Path;

use tracing_subscriber::{fmt, EnvFilter};

use crate::config::{LogFormat, LoggingSettings};

/// Guardia che deve rimanere viva per tutta la durata del processo affinché
/// il logging su file (asincrono, tramite `tracing-appender`) continui a
/// scrivere correttamente; il chiamante (`main.rs`) la mantiene in uno
/// scope non droppato fino alla fine del programma.
pub struct TelemetryGuard {
    _file_guard: Option<tracing_appender::non_blocking::WorkerGuard>,
}

/// Inizializza il subscriber globale di `tracing` in base alle impostazioni
/// di logging. Va chiamata una sola volta, il prima possibile in `main`.
pub fn init_tracing(settings: &LoggingSettings) -> TelemetryGuard {
    let env_filter = EnvFilter::try_new(&settings.level)
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let (file_guard, file_writer) = match &settings.directory {
        Some(dir) => {
            let (writer, guard) = build_file_writer(dir);
            (Some(guard), Some(writer))
        }
        None => (None, None),
    };

    let builder = fmt::Subscriber::builder().with_env_filter(env_filter);

    match (&settings.format, file_writer) {
        (LogFormat::Json, Some(writer)) => {
            builder.json().with_writer(writer).init();
        }
        (LogFormat::Json, None) => {
            builder.json().init();
        }
        (LogFormat::Pretty, Some(writer)) => {
            builder.pretty().with_writer(writer).init();
        }
        (LogFormat::Pretty, None) => {
            builder.pretty().init();
        }
        (LogFormat::Compact, Some(writer)) => {
            builder.compact().with_writer(writer).init();
        }
        (LogFormat::Compact, None) => {
            builder.compact().init();
        }
    }

    TelemetryGuard {
        _file_guard: file_guard,
    }
}

fn build_file_writer(
    directory: &Path,
) -> (
    tracing_appender::non_blocking::NonBlocking,
    tracing_appender::non_blocking::WorkerGuard,
) {
    let file_appender = tracing_appender::rolling::daily(directory, "kerneltrace.log");
    tracing_appender::non_blocking(file_appender)
}