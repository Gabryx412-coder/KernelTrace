//! Modulo di loading: attach dei programmi eBPF e lettura del ring buffer.

mod attacher;
mod ringbuf_reader;

pub use attacher::{attach_process_probes, check_privileges, load_ebpf_object};
pub use ringbuf_reader::{run_ringbuf_reader, take_ring_buffer};