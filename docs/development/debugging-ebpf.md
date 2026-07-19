# Debug delle probe eBPF

## Verificare gli offset dei tracepoint

Le probe che leggono argomenti tramite offset fissi (es.
`SYS_ENTER_ARG1_OFFSET` in `probes/file.rs`) assumono un layout stabile
del formato tracepoint. **Prima di distribuire su un nuovo kernel target**,
verifica sempre il formato reale:

```bash
sudo cat /sys/kernel/tracing/events/syscalls/sys_enter_openat/format
```

Confronta gli offset (`field:... offset:N`) con le costanti usate nel
codice Rust corrispondente.

## Log delle probe tramite `aya-log`

Le probe possono includere `aya_log_ebpf::info!`/`warn!` per il logging
diagnostico, letto lato userspace tramite `aya-log`. Non incluso nella
build di produzione per non introdurre overhead, ma utile durante lo
sviluppo di nuove probe: vedi la documentazione di `aya-log` per
l'integrazione.

## Ispezionare i programmi caricati

```bash
sudo bpftool prog list
sudo bpftool prog dump xlated id <PROG_ID>
```

## Errori comuni di verifica del BPF verifier

- **"invalid indirect read from stack"**: quasi sempre causato da un
  loop non dimostrabilmente `bounded` — verifica che ogni ciclo abbia un
  limite costante esplicito (vedi `MAX_EXEC_ARGS` in `probes/process.rs`).
- **"invalid access to packet"** o simili su `bpf_probe_read_user`:
  verifica che il puntatore letto sia effettivamente un puntatore
  user-space valido all'offset atteso (vedi la sezione sugli offset sopra).
- **"program is too large"**: il limite storico di 4096 istruzioni per
  programma BPF è stato progressivamente alzato nei kernel recenti (fino
  a 1 milione su kernel ≥ 5.2), ma su kernel più vecchi può essere
  necessario suddividere una probe complessa in più tail call.

## Test isolato di una singola probe

```bash
cd crates/kerneltrace-ebpf
cargo +nightly build -Z build-std=core --target bpfel-unknown-none
sudo bpftool prog load target/bpfel-unknown-none/debug/kerneltrace-ebpf /sys/fs/bpf/kerneltrace-test
sudo bpftool prog show pinned /sys/fs/bpf/kerneltrace-test
sudo rm /sys/fs/bpf/kerneltrace-test
```