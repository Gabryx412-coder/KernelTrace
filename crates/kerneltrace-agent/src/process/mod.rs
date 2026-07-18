//! Process monitoring lato userspace: process tree, rilevamento di
//! processi orfani/zombie, e rilevamento di privilege escalation.

pub mod lifecycle;
pub mod privilege;
pub mod tree;

pub use lifecycle::{is_orphaned, LifecycleFinding, OrphanZombieScanner, ProcessState};
pub use privilege::{PrivilegeEscalationEnricher, PRIVILEGE_ESCALATION_TAG};
pub use tree::{ProcessNode, ProcessTree, ProcessTreeEnricher};