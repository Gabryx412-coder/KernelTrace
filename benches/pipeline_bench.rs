//! Benchmark della pipeline eventi: misura il throughput di
//! normalizzazione + arricchimento per eventi `exec`, il tipo di evento
//! più frequente su un host tipico.
//!
//! Questo benchmark misura l'overhead **userspace** della pipeline, non
//! l'overhead complessivo di sistema (che include il costo delle probe
//! eBPF stesse, non misurabile in un benchmark `criterion` che gira senza
//! privilegi kernel). Per la metodologia di misurazione dell'overhead
//! complessivo end-to-end (`< 2%` target di progetto), vedi
//! `docs/performance/benchmarks.md`.

use std::sync::Arc;

use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use kerneltrace_agent::events::{enrich_with, normalize, Enricher, NoopEnricher};
use kerneltrace_agent::process::{ProcessTree, ProcessTreeEnricher};
use kerneltrace_common::{EventHeader, EventType, ExecEvent};

fn sample_exec_bytes() -> Bytes {
    let header = EventHeader {
        event_type: EventType::Exec as u32,
        timestamp_ns: 123_456_789,
        pid: 4242,
        tgid: 4242,
        ppid: 1,
        uid: 1000,
        gid: 1000,
        cgroup_id: 0,
        comm: {
            let mut c = [0u8; 16];
            c[..4].copy_from_slice(b"bash");
            c
        },
    };

    let mut filename = [0u8; 256];
    filename[..9].copy_from_slice(b"/bin/bash");

    let event = ExecEvent {
        header,
        filename,
        filename_len: 9,
        argc: 0,
        argv: [[0u8; 64]; 8],
        argv_len: [0u16; 8],
    };

    let bytes = unsafe {
        std::slice::from_raw_parts(&event as *const _ as *const u8, std::mem::size_of::<ExecEvent>())
    };
    Bytes::copy_from_slice(bytes)
}

fn bench_normalize_only(c: &mut Criterion) {
    let raw = sample_exec_bytes();

    c.bench_function("normalize_exec_event", |b| {
        b.iter(|| {
            let event = normalize(black_box(&raw)).expect("should normalize");
            black_box(event);
        })
    });
}

fn bench_normalize_and_enrich(c: &mut Criterion) {
    let raw = sample_exec_bytes();
    let tree = Arc::new(ProcessTree::new());
    let enrichers: Vec<Box<dyn Enricher>> = vec![
        Box::new(ProcessTreeEnricher::new(Arc::clone(&tree))),
        Box::new(NoopEnricher),
    ];

    c.bench_function("normalize_and_enrich_exec_event", |b| {
        b.iter(|| {
            let mut event = normalize(black_box(&raw)).expect("should normalize");
            enrich_with(&mut event, &enrichers);
            black_box(event);
        })
    });
}

criterion_group!(benches, bench_normalize_only, bench_normalize_and_enrich);
criterion_main!(benches);