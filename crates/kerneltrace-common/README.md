# kerneltrace-common

Tipi condivisi tra i programmi eBPF (`crates/kerneltrace-ebpf`) e l'agente
userspace (`crates/kerneltrace-agent`).

## Perché esiste questo crate

I programmi eBPF girano in un ambiente `no_std` estremamente vincolato (nessun
allocatore, stack limitato, nessuna libreria standard). Per evitare
duplicazione e disallineamenti tra le strutture dati scritte nel ring buffer
dal kernel e quelle lette dall'agente in userspace, tutte le definizioni degli
eventi vivono in un unico crate condiviso, compilato sia per il target BPF
(`bpfel-unknown-none` / `bpfeb-unknown-none`) sia per il target nativo
dell'host (`x86_64-unknown-linux-gnu`, ecc.).

## Contenuto

| Modulo | Contenuto |
|---|---|
| `constants` | Limiti fissi (lunghezza `comm`, lunghezza path, ecc.) condivisi da probe e agente |
| `syscalls` | Enum `SyscallId` con l'elenco delle syscall monitorate |
| `events` | Struct `#[repr(C)]` degli eventi raw scritti nel ring buffer BPF |
| `error` | Tipo di errore comune, `no_std`-compatibile |

## Feature flag

- **default (no_std)**: usato dal crate `kerneltrace-ebpf`.
- **`std`**: abilita `serde::Serialize`/`Deserialize` sulle strutture eventi,
  usato dal crate `kerneltrace-agent` per la normalizzazione e l'output JSON.

## Vincoli di design

- Tutte le struct degli eventi sono `#[repr(C)]`, `Copy`, a dimensione fissa:
  nessun puntatore, nessuna allocazione, per poter essere scritte da un
  programma eBPF e lette come blocco di byte grezzo dallo userspace.
- Le stringhe (nomi file, `comm`, ecc.) sono rappresentate come array di byte
  a lunghezza fissa (`[u8; N]`) più un campo di lunghezza effettiva.