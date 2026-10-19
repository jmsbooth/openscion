//! FOSS-491 debug-only deterministic publication checkpoint protocol.
//!
//! NOT included in default builds. The sole purpose is to pause an explicit
//! disposable test process at a named source boundary for external SIGKILL /
//! TerminateProcess. A marker is evidence that this code path executed, not
//! cryptographic proof of host identity, Windows NTFS durability or power loss.
#![forbid(unsafe_code)]

use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, ErrorKind, Write};
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

pub(super) const POINTS: [&str; 12] = [
    "object_before_stage_fsync",
    "object_after_stage_fsync",
    "object_before_publish",
    "object_after_publish",
    "object_before_stage_remove",
    "object_after_stage_remove",
    "object_before_parent_sync",
    "object_after_parent_sync",
    "checkout_before_publish",
    "checkout_after_publish",
    "checkout_before_parent_sync",
    "checkout_after_parent_sync",
];

fn rejected(message: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidInput, message)
}

/// With no checkpoint selection, even a QA binary behaves like the normal
/// store. Only the specifically selected point pauses. There is no release
/// build code path because the module is compiled solely behind a Cargo feature.
pub(super) fn checkpoint(point: &'static str) -> io::Result<()> {
    if !POINTS.contains(&point) {
        return Err(rejected("unrecognized source checkpoint"));
    }
    let selected = match env::var("OPENSCION_QA_CUTPOINT") {
        Ok(value) => value,
        Err(env::VarError::NotPresent) => return Ok(()),
        Err(env::VarError::NotUnicode(_)) => return Err(rejected("invalid checkpoint selector")),
    };
    if !POINTS.contains(&selected.as_str()) {
        return Err(rejected("unknown requested checkpoint"));
    }
    if selected != point {
        return Ok(());
    }

    let nonce = env::var("OPENSCION_QA_NONCE")
        .map_err(|_| rejected("checkpoint nonce missing or invalid"))?;
    if nonce.len() != 32
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(rejected("invalid checkpoint nonce"));
    }
    let directory = PathBuf::from(
        env::var_os("OPENSCION_QA_MARKER_DIR")
            .ok_or_else(|| rejected("checkpoint marker directory is missing"))?,
    );
    let attributes = fs::symlink_metadata(&directory)?;
    if attributes.file_type().is_symlink() || !attributes.is_dir() {
        return Err(rejected("checkpoint marker directory must not be a link"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if attributes.file_attributes() & 0x400 != 0 {
            return Err(rejected("checkpoint marker directory is a reparse point"));
        }
    }

    // One source marker per test child. create_new rejects stale/replayed
    // marker names, and the flush precedes the indefinite-in-production,
    // strictly time-bounded QA-only pause.
    let marker = directory.join(format!("{nonce}.{point}.hit"));
    let mut file = OpenOptions::new().write(true).create_new(true).open(marker)?;
    write!(
        file,
        "v1\npoint={point}\nnonce={nonce}\npid={}\n",
        std::process::id()
    )?;
    file.sync_all()?;
    drop(file);

    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(30) {
        thread::sleep(Duration::from_millis(10));
    }
    Err(io::Error::new(
        ErrorKind::TimedOut,
        "QA checkpoint timed out without external termination",
    ))
}

#[cfg(test)]
mod tests {
    use super::POINTS;
    use std::collections::BTreeSet;

    #[test]
    fn names_are_canonical_and_unique() {
        assert_eq!(POINTS.len(), 12);
        assert_eq!(POINTS.iter().copied().collect::<BTreeSet<_>>().len(), POINTS.len());
        assert!(POINTS.iter().all(|name| name.starts_with("object_") || name.starts_with("checkout_")));
    }
}
