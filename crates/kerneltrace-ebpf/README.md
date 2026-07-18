# kerneltrace-ebpf

Programmi eBPF (CO-RE) che implementano le probe a livello kernel di
KernelTrace, scritti in Rust con [`aya-ebpf`](https://aya-rs.dev/).

## Come funziona

Ogni probe è agganciata a un **tracepoint** stabile del kernel (preferiti
rispetto ai kprobe quando disponibili, perché fanno parte dell'ABI stabile
del kernel e non dipendono dai nomi interni delle funzioni, che possono
cambiare tra versioni). Al verificarsi dell'evento, la probe:

1. legge il contesto del processo corrente (`pid`, `tgid`, `uid`, `gid`,
   `comm`, `cgroup_id`) tramite le helper di `aya-ebpf`;
2. costruisce una struct evento `#[repr(C)]` definita in `kerneltrace-common`;
3. la scrive in un **ring buffer BPF** (`RingBuf`), letto in modo asincrono
   dall'agente userspace tramite `aya::maps::RingBuf` + un task `tokio`
   dedicato (vedi `kerneltrace-agent::loader::ringbuf_reader`).

Questo approccio (ring buffer invece di `perf event array`) riduce
significativamente l'overhead di copia e il rischio di perdita di eventi
sotto carico, contribuendo all'obiettivo di overhead complessivo `< 2%`.

## Struttura

| File | Probe implementate |
|---|---|
| `probes/process.rs` | `execve`, `execveat`, `clone`, `fork`, `vfork` |
| `probes/file.rs` | `open`, `openat`, `unlink`, `rename`, `chmod`, `chown` *(Parte 6)* |
| `probes/network.rs` | `connect`, `accept`, `bind`, `listen` *(Parte 6)* |
| `probes/privilege.rs` | `ptrace`, `setuid`, `setgid` *(Parte 6)* |
| `probes/memory.rs` | `mmap` *(Parte 6)* |
| `probes/signal.rs` | `kill` *(Parte 6)* |
| `probes/mount.rs` | `mount`, `umount` *(Parte 6)* |
| `maps.rs` | Definizione delle mappe BPF condivise (ring buffer, hash map di tracking) |

## Vincoli dell'ambiente eBPF

- **`no_std`**, nessun allocatore: tutte le struct sono a dimensione fissa.
- **Stack limitato a 512 byte per programma**: le struct evento sono tenute
  deliberatamente compatte (vedi `kerneltrace-common::events`) e, quando
  necessario, allocate direttamente nello spazio riservato dal ring buffer
  tramite `RingBuf::reserve` per evitare copie intermedie sullo stack.
- **BPF verifier**: ogni accesso a memoria e ogni loop devono essere
  dimostrabilmente limitati; i loop su `argv` in `probes/process.rs` sono
  quindi `bounded` con un limite costante (`MAX_EXEC_ARGS`).

## Build

Vedi [docs/development/building.md](../../docs/development/building.md) per
la procedura di build completa (richiede toolchain `nightly` con
`rust-src` e target `bpfel-unknown-none`/`bpfeb-unknown-none`).