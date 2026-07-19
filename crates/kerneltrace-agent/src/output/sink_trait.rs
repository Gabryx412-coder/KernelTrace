//! Trait comune a tutti gli output sink di KernelTrace.
//!
//! Il trait è deliberatamente sincrono (nessun `async fn` in trait,
//! evitando così una dipendenza aggiuntiva come `async-trait`): la
//! scrittura su stdout o su file è un'operazione già molto rapida, e viene
//! eseguita all'interno di un task `tokio` dedicato tramite
//! `spawn_blocking` quando necessario (vedi `OutputManager::dispatch`),
//! così da non bloccare il runtime asincrono anche in caso di I/O lento
//! su filesystem di rete.
//!
//! Sink futuri verso sistemi esterni (Elastic, Splunk, Kafka) potranno
//! implementare questo stesso trait usando client HTTP/TCP asincroni
//! internamente, incapsulando l'attesa di rete dietro un blocco
//! `tokio::runtime::Handle::block_on` o, più idiomaticamente, convertendo
//! il trait in una versione `async_trait` quando quel primo sink di rete
//! verrà introdotto — un cambiamento isolato a questo modulo, senza
//! impatto sul resto della pipeline.

use crate::error::AgentResult;
use crate::events::NormalizedEvent;

/// Un sink riceve eventi normalizzati (già arricchiti e valutati dal
/// rules engine) e li scrive verso una destinazione esterna.
pub trait Sink: Send + Sync {
    /// Nome del sink, usato nei log diagnostici e nei messaggi di errore.
    fn name(&self) -> &'static str;

    /// Scrive un singolo evento verso la destinazione del sink.
    ///
    /// Un errore qui viene loggato dal chiamante (`OutputManager`) ma non
    /// interrompe la scrittura sugli altri sink configurati: un sink che
    /// fallisce (es. disco pieno) non deve impedire agli altri sink di
    /// continuare a funzionare.
    fn write_event(&self, event: &NormalizedEvent) -> AgentResult<()>;

    /// Forza il flush di eventuali buffer interni. Chiamato periodicamente
    /// e allo shutdown dell'agente. L'implementazione di default è no-op,
    /// adatta ai sink che scrivono immediatamente (es. stdout non
    /// bufferizzato).
    fn flush(&self) -> AgentResult<()> {
        Ok(())
    }
}