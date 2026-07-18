//! File Integrity Monitoring: baseline in memoria, hashing dei file
//! monitorati, e watcher che collega gli eventi di file alla baseline.

pub mod baseline;
pub mod hash;
pub mod watcher;

pub use baseline::{Baseline, BaselineDeviation, FileBaselineEntry};
pub use hash::{hash_file, HashAlgorithm};
pub use watcher::{
    FimWatcher, TAG_FIM_CONTENT_CHANGED, TAG_FIM_OWNER_CHANGED, TAG_FIM_PERMISSIONS_CHANGED,
    TAG_FIM_UNTRACKED_PATH,
};