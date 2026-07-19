# Esecuzione dei test

## Unit test

```bash
cargo test --workspace --exclude kerneltrace-ebpf
```

Il crate `kerneltrace-ebpf` è escluso perché `no_std` e compilato per un
target BPF: non esegue in un ambiente di test standard (vedi
[debugging-ebpf.md](debugging-ebpf.md) per come validare le probe).

## Integration test

```bash
cargo test --workspace --exclude kerneltrace-ebpf --test '*'
```

Gli integration test in `tests/integration/` esercitano l'API pubblica di
`kerneltrace-agent` end-to-end tra più moduli (es. process tree +
enricher, baseline FIM + watcher su file reali, regole built-in caricate
da disco).

## Benchmark

```bash
cd crates/kerneltrace-agent
cargo bench --bench pipeline_bench
cargo bench --bench detection_bench
```

Vedi [performance/benchmarks.md](../performance/benchmarks.md) per
l'interpretazione dei risultati e i limiti metodologici.

## Fuzzing

```bash
cargo install cargo-fuzz
cd fuzz
cargo +nightly fuzz run fuzz_event_normalizer -- -max_total_time=300
```

Target disponibili: `fuzz_rule_parser`, `fuzz_event_normalizer`,
`fuzz_config_loader`.

## Test del tool Python

```bash
cd management
pytest --cov=kerneltrace_mgmt
```

## Coverage complessiva

```bash
cargo install cargo-tarpaulin
cargo tarpaulin --workspace --exclude kerneltrace-ebpf --out Html
```