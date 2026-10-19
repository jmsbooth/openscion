//! Immutable typed content-addressed objects.
//!
//! Only blobs and canonical path snapshots exist in v1. This is not a
//! revision system, authorization service or provenance mechanism.

// A security-sensitive checkpoint path exists only in an explicitly built
// debug/QA executable and is rejected by release/profile builds.
#[cfg(all(feature = "qa-fault-injection", not(debug_assertions)))]
compile_error!("qa-fault-injection is forbidden when debug_assertions are disabled");

#[cfg(feature = "qa-fault-injection")]
mod fault;
mod identity;
mod safe_path;
mod snapshot;
mod store;

pub use identity::{ObjectId, ObjectKind};
pub use snapshot::{Snapshot, SnapshotEntry};
pub use store::ObjectStore;

use std::fmt;

/// Explicit allocation/persistence limits for local M1 objects.
pub const MAX_BLOB_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_SNAPSHOT_BYTES: usize = 8 * 1024 * 1024;
/// Conservative local MVP limits to bound reference-validation and checkout cost.
pub const MAX_SNAPSHOT_ENTRIES: usize = 4096;
pub const MAX_SNAPSHOT_MATERIALIZED_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectErrorKind {
    InvalidId,
    WrongType,
    TooLarge,
    Missing,
    Corrupt,
    InvalidSnapshot,
    UnsafePath,
    AlreadyExists,
    InvalidStore,
    Io,
}

impl ObjectErrorKind {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidId => "E_OBJECT_ID",
            Self::WrongType => "E_OBJECT_TYPE",
            Self::TooLarge => "E_OBJECT_SIZE",
            Self::Missing => "E_OBJECT_MISSING",
            Self::Corrupt => "E_OBJECT_CORRUPT",
            Self::InvalidSnapshot => "E_SNAPSHOT_INVALID",
            Self::UnsafePath => "E_UNSAFE_PATH",
            Self::AlreadyExists => "E_ALREADY_EXISTS",
            Self::InvalidStore => "E_INVALID_STORE",
            Self::Io => "E_IO",
        }
    }

    pub const fn exit_code(self) -> u8 {
        match self {
            Self::InvalidId | Self::WrongType | Self::TooLarge | Self::InvalidSnapshot => 8,
            Self::Missing => 9,
            Self::Corrupt => 10,
            Self::UnsafePath => 3,
            Self::AlreadyExists => 5,
            Self::InvalidStore => 6,
            Self::Io => 7,
        }
    }
}

#[derive(Debug)]
pub struct ObjectError {
    pub kind: ObjectErrorKind,
    pub message: String,
}

impl ObjectError {
    pub(crate) fn new(kind: ObjectErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub(crate) fn io(action: &'static str, cause: std::io::Error) -> Self {
        Self::new(ObjectErrorKind::Io, format!("{action}: {cause}"))
    }
}

impl fmt::Display for ObjectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ObjectError {}
