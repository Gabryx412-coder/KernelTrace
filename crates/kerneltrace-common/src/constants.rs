//! Costanti condivise tra i programmi eBPF e l'agente userspace.
//!
//! Questi limiti sono deliberatamente fissi (nessuna allocazione dinamica)
//! perché devono valere sia lato kernel (eBPF verifier, stack limitato a 512
//! byte per programma) sia lato userspace, dove devono corrispondere
//! esattamente al layout di memoria scritto dal kernel nel ring buffer.

/// Lunghezza massima del nome del processo (`task->comm` nel kernel Linux).
pub const MAX_COMM_LEN: usize = 16;

/// Lunghezza massima memorizzata per i path di file (troncati oltre questo limite).
///
/// 256 byte coprono la stragrande maggioranza dei path reali senza far
/// esplodere lo stack del programma eBPF (che ha un limite di 512 byte).
pub const MAX_PATH_LEN: usize = 256;

/// Numero massimo di argomenti di `execve` catturati per evento.
pub const MAX_EXEC_ARGS: usize = 8;

/// Lunghezza massima per singolo argomento di `execve` catturato.
pub const MAX_EXEC_ARG_LEN: usize = 64;

/// Dimensione massima di un indirizzo IP memorizzato (16 byte = IPv6, IPv4
/// mappato come IPv4-mapped IPv6 address).
pub const IP_ADDR_LEN: usize = 16;

/// Dimensione del ring buffer BPF usato per il trasporto degli eventi, in byte.
///
/// Deve essere una potenza di 2. 16 MiB è un compromesso tra throughput sotto
/// carico e footprint di memoria kernel, in linea con l'obiettivo di overhead
/// complessivo inferiore al 2%.
pub const RING_BUFFER_SIZE_BYTES: u32 = 16 * 1024 * 1024;

/// Capacità massima della mappa BPF usata per tracciare i processi attivi
/// (process tree, correlazione parent-child).
pub const MAX_TRACKED_PROCESSES: u32 = 65536;

/// Capacità massima della mappa BPF usata per il baseline del File Integrity
/// Monitoring (path monitorati attivamente).
pub const MAX_FIM_WATCHED_PATHS: u32 = 8192;

/// Lunghezza massima dell'identificatore di cgroup usato per il container
/// awareness (troncato se più lungo, ma i cgroup id sono numerici a 64 bit
/// quindi normalmente non serve troncare — vedi `events::EventHeader::cgroup_id`).
pub const MAX_CONTAINER_ID_LEN: usize = 64;