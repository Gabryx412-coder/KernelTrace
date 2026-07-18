//! Network monitoring: connection tracking, rilevamento reverse shell e
//! rilevamento beaconing, applicati agli eventi di rete normalizzati.

pub mod beaconing;
pub mod connections;
pub mod reverse_shell;

pub use beaconing::{BeaconingDetector, BeaconingTracker, TAG_SUSPECTED_BEACONING};
pub use connections::{
    ConnectionDirection, ConnectionKey, ConnectionState, ConnectionTracker,
    ConnectionTrackerEnricher,
};
pub use reverse_shell::{ReverseShellDetector, TAG_SUSPECTED_REVERSE_SHELL};