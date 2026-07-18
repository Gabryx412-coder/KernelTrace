//! Arricchimento degli eventi normalizzati con contesto aggiuntivo
//! (container, informazioni derivate dal process tree, ecc.).
//!
//! In questa parte implementiamo solo l'interfaccia e un arricchimento
//! minimo; l'integrazione completa con `process::tree` e `container::*`
//! avviene nelle Parti 5 e 9, che popoleranno le funzioni sottostanti senza
//! richiedere modifiche alla firma pubblica di `enrich`.

use tracing::warn;

use super::types::NormalizedEvent;

/// Trait che astrae una fase di arricchimento della pipeline, per
/// permettere di comporre più arricchitori (container, process tree, FIM
/// hash) senza accoppiare `enrich` a implementazioni concrete.
pub trait Enricher: Send + Sync {
    fn enrich(&self, event: &mut NormalizedEvent);
}

/// Arricchitore no-op, usato come default finché gli arricchitori concreti
/// (container awareness, process tree) non sono implementati.
pub struct NoopEnricher;

impl Enricher for NoopEnricher {
    fn enrich(&self, _event: &mut NormalizedEvent) {}
}

/// Applica in sequenza una lista di arricchitori a un evento normalizzato.
pub fn enrich_with(event: &mut NormalizedEvent, enrichers: &[Box<dyn Enricher>]) {
    for enricher in enrichers {
        enricher.enrich(event);
    }
    if enrichers.is_empty() {
        warn!(
            event_id = %event.id,
            "no enrichers configured; event will be forwarded without container/process context"
        );
    }
}