//! Pipeline eventi: canale asincrono con backpressure tra il ring buffer
//! reader e gli stadi successivi (arricchimento, detection, output).

use bytes::Bytes;
use tokio::sync::mpsc;
use tracing::{error, warn};

use super::enrichment::Enricher;
use super::normalizer::normalize;
use super::types::NormalizedEvent;

/// Canale con backpressure che disaccoppia il produttore di byte grezzi
/// (ring buffer reader) dal consumatore di eventi normalizzati (detection
/// engine). La dimensione del canale è configurabile
/// (`agent.pipeline_capacity`) per bilanciare latenza e uso di memoria.
pub struct EventPipeline {
    raw_sender: mpsc::Sender<Bytes>,
    raw_receiver: mpsc::Receiver<Bytes>,
}

impl EventPipeline {
    /// Crea una nuova pipeline con la capacità di canale specificata.
    pub fn new(capacity: usize) -> Self {
        let (raw_sender, raw_receiver) = mpsc::channel(capacity);
        Self {
            raw_sender,
            raw_receiver,
        }
    }

    /// Restituisce un handle clonabile per inviare byte grezzi alla
    /// pipeline (usato dal ring buffer reader).
    pub fn sender(&self) -> mpsc::Sender<Bytes> {
        self.raw_sender.clone()
    }

    /// Consuma la pipeline, restituendo uno stream di eventi normalizzati e
    /// arricchiti, pronti per il detection engine.
    ///
    /// Ogni blocco di byte che fallisce la normalizzazione (formato
    /// inatteso, tipo di evento sconosciuto) viene scartato con un
    /// warning, senza interrompere il flusso degli eventi successivi:
    /// un singolo evento malformato non deve mai bloccare l'intera pipeline.
    pub async fn run(
        mut self,
        enrichers: Vec<Box<dyn Enricher>>,
        output_sender: mpsc::Sender<NormalizedEvent>,
    ) {
        // Rilasciamo il sender originale mantenuto in `self` per evitare
        // che il canale resti aperto indefinitamente dopo che tutti i
        // produttori (ring buffer reader) sono terminati.
        drop(self.raw_sender);

        while let Some(raw) = self.raw_receiver.recv().await {
            let mut event = match normalize(&raw) {
                Ok(event) => event,
                Err(err) => {
                    warn!(error = %err, "discarding malformed event");
                    continue;
                }
            };

            super::enrichment::enrich_with(&mut event, &enrichers);

            if output_sender.send(event).await.is_err() {
                error!("downstream consumer channel closed, stopping pipeline");
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kerneltrace_common::{EventHeader, EventType, ProcessLifecycleEvent};

    fn sample_raw_event() -> Bytes {
        let header = EventHeader {
            event_type: EventType::ProcessLifecycle as u32,
            timestamp_ns: 1,
            pid: 1,
            tgid: 1,
            ppid: 0,
            uid: 0,
            gid: 0,
            cgroup_id: 0,
            comm: [0u8; 16],
        };
        let event = ProcessLifecycleEvent {
            header,
            syscall_id: 8,
            exit_code: 0,
            is_orphan: 0,
            is_zombie: 0,
            _padding: [0u8; 6],
        };
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &event as *const _ as *const u8,
                std::mem::size_of::<ProcessLifecycleEvent>(),
            )
        };
        Bytes::copy_from_slice(bytes)
    }

    #[tokio::test]
    async fn pipeline_forwards_valid_events() {
        let pipeline = EventPipeline::new(16);
        let raw_sender = pipeline.sender();
        let (output_sender, mut output_receiver) = mpsc::channel(16);

        raw_sender.send(sample_raw_event()).await.unwrap();
        drop(raw_sender);

        pipeline
            .run(vec![Box::new(super::super::enrichment::NoopEnricher)], output_sender)
            .await;

        let received = output_receiver.recv().await;
        assert!(received.is_some());
    }

    #[tokio::test]
    async fn pipeline_discards_malformed_events_without_stopping() {
        let pipeline = EventPipeline::new(16);
        let raw_sender = pipeline.sender();
        let (output_sender, mut output_receiver) = mpsc::channel(16);

        raw_sender.send(Bytes::from_static(&[0u8; 2])).await.unwrap();
        raw_sender.send(sample_raw_event()).await.unwrap();
        drop(raw_sender);

        pipeline
            .run(vec![Box::new(super::super::enrichment::NoopEnricher)], output_sender)
            .await;

        let received = output_receiver.recv().await;
        assert!(received.is_some(), "valid event after malformed one should still arrive");
    }
}