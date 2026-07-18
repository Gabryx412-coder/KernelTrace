//! Event pipeline: normalizzazione, arricchimento, canale asincrono.

mod enrichment;
mod normalizer;
mod pipeline;
mod types;

pub use enrichment::{enrich_with, Enricher, NoopEnricher};
pub use normalizer::normalize;
pub use pipeline::EventPipeline;
pub use types::{
    ContainerContext, ContainerRuntime, EventKind, EventPayload, NormalizedEvent, ProcessContext,
};