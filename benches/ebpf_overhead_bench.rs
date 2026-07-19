//! Placeholder di benchmark per l'overhead delle probe eBPF.
//!
//! # Limite metodologico importante
//!
//! `criterion` esegue codice Rust in un processo userspace ordinario,
//! **non può misurare l'overhead reale introdotto dalle probe eBPF nel
//! kernel** (context switch, esecuzione del programma BPF verificato,
//! scrittura sul ring buffer): quella misurazione richiede strumenti
//! esterni al processo di build (`perf stat`, `bpftrace`, o un carico di
//! lavoro sintetico A/B con e senza KernelTrace attivo), documentati in
//! dettaglio in `docs/performance/benchmarks.md`.
//!
//! Questo benchmark misura invece un **proxy utile**: il costo puramente
//! userspace di parsing e dispatch di un evento, che è comunque una
//! componente diretta dell'overhead complessivo percepito (più veloce è
//! questo stadio, meno probabile che il ring buffer si riempia sotto
//! carico, riducendo la pressione sul lato kernel).

use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use kerneltrace_agent::events::normalize;
use kerneltrace_common::{EventHeader, EventType, NetworkEvent};

fn sample_network_event_bytes() -> Bytes {
    let header = EventHeader {
        event_type: EventType::Connect as u32,
        timestamp_ns: 42,
        pid: 100,
        tgid: 100,
        ppid: 1,
        uid: 0,
        gid: 0,
        cgroup_id: 0,
        comm: [0u8; 16],
    };

    let mut dst_addr = [0u8; 16];
    dst_addr[0..4].copy_from_slice(&[93, 184, 216, 34]);

    let event = NetworkEvent {
        header,
        address_family: 4,
        protocol: 6,
        _padding: [0u8; 2],
        src_addr: [0u8; 16],
        dst_addr,
        src_port: 0,
        dst_port: 443,
        syscall_id: 4,
    };

    let bytes = unsafe {
        std::slice::from_raw_parts(&event as *const _ as *const u8, std::mem::size_of::<NetworkEvent>())
    };
    Bytes::copy_from_slice(bytes)
}

fn bench_network_event_dispatch_overhead(c: &mut Criterion) {
    let raw = sample_network_event_bytes();

    c.bench_function("userspace_dispatch_overhead_proxy", |b| {
        b.iter(|| {
            let event = normalize(black_box(&raw)).expect("should normalize");
            black_box(event);
        })
    });
}

criterion_group!(benches, bench_network_event_dispatch_overhead);
criterion_main!(benches);