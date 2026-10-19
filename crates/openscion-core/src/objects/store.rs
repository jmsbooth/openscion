use super::identity::{ObjectId, ObjectKind};
use super::safe_path::validate_path;
use super::snapshot::{Snapshot, SnapshotEntry};
use super::{
    ObjectError, ObjectErrorKind, MAX_BLOB_BYTES, MAX_SNAPSHOT_BYTES,
    MAX_SNAPSHOT_MATERIALIZED_BYTES,
};
use crate::{inspect_repository, is_link_like, validate_directory, ErrorCode};
#[cfg(not(windows))]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

/// Validated local repository store. No mutable revision or branch pointers.
///
/// Clone is deliberately not implemented. Sharing with Arc is safe for
/// concurrent identical writes, subject to the documented local user trust.
#[derive(Debug)]
pub struct ObjectStore {
    root: PathBuf,
}

impl ObjectStore {
    pub fn open(repository: &Path) -> Result<Self, ObjectError> {
        let info = inspect_repository(repository).map_err(|failure| {
            let kind = if failure.code == ErrorCode::UnsafePath {
                ObjectErrorKind::UnsafePath
            } else {
                ObjectErrorKind::InvalidStore
            };
            ObjectError::new(kind, failure.message)
        })?;
        Ok(Self { root: info.root })
    }

    pub fn put_blob(&self, bytes: &[u8]) -> Result<ObjectId, ObjectError> {
        self.put_object(ObjectKind::Blob, bytes)
    }

    pub fn get_blob(&self, id: &ObjectId) -> Result<Vec<u8>, ObjectError> {
        self.get_object(id, ObjectKind::Blob)
    }

    pub fn put_snapshot(&self, entries: &[SnapshotEntry]) -> Result<ObjectId, ObjectError> {
        let snapshot = Snapshot::new(entries)?;
        self.verify_snapshot_entries(snapshot.entries())?;
        self.put_object(ObjectKind::Snapshot, &snapshot.encode())
    }

    pub fn get_snapshot(&self, id: &ObjectId) -> Result<Vec<SnapshotEntry>, ObjectError> {
        let bytes = self.get_object(id, ObjectKind::Snapshot)?;
        let entries = Snapshot::decode(&bytes)?.entries().to_vec();
        self.verify_snapshot_entries(&entries)?;
        Ok(entries)
    }

    fn verify_snapshot_entries(&self, entries: &[SnapshotEntry]) -> Result<(), ObjectError> {
        let mut aggregate_bytes = 0usize;
        for entry in entries {
            let bytes = self.get_blob(&entry.blob)?;
            aggregate_bytes = aggregate_bytes.checked_add(bytes.len()).ok_or_else(|| {
                ObjectError::new(ObjectErrorKind::TooLarge, "snapshot content size overflow")
            })?;
            if aggregate_bytes > MAX_SNAPSHOT_MATERIALIZED_BYTES {
                return Err(ObjectError::new(
                    ObjectErrorKind::TooLarge,
                    "snapshot exceeds local materialization budget",
                ));
            }
        }
        Ok(())
    }

    /// Import a source file from inside the repository using a portable
    /// relative name. Nonregular files and symlinks are never dereferenced.
    pub fn put_repo_file(&self, relative: &str) -> Result<ObjectId, ObjectError> {
        let bytes = self.read_repo_file(relative, MAX_BLOB_BYTES)?;
        self.put_blob(&bytes)
    }

    /// Bounded repo-relative file read, used for file and manifest ingestion.
    pub fn read_repo_file(&self, relative: &str, limit: usize) -> Result<Vec<u8>, ObjectError> {
        validate_path(relative)?;
        let components: Vec<&str> = relative.split('/').collect();
        let mut current = self.root.clone();
        for (index, component) in components.iter().enumerate() {
            current.push(component);
            let metadata = metadata(&current)?;
            if is_link_like(&metadata) {
                return Err(unsafe_path());
            }
            let final_component = index == components.len() - 1;
            if final_component && !metadata.is_file() || !final_component && !metadata.is_dir() {
                return Err(unsafe_path());
            }
        }
        read_bounded(&current, limit, false)
    }

    /// Materialize a full verified snapshot into a *nonexistent* directory.
    ///
    /// No committed revisions exist yet. This operation only exposes file
    /// bytes from a known snapshot in a disposable local workspace.
    pub fn materialize(
        &self,
        snapshot_id: &ObjectId,
        destination: &Path,
    ) -> Result<(), ObjectError> {
        let entries = self.get_snapshot(snapshot_id)?;
        if destination
            .components()
            .any(|component| component == std::path::Component::ParentDir)
        {
            return Err(unsafe_path());
        }
        let basename = destination.file_name().ok_or_else(unsafe_path)?;
        if basename == std::ffi::OsStr::new(".") || basename == std::ffi::OsStr::new("..") {
            return Err(unsafe_path());
        }
        let parent = destination
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let safe_parent = validate_directory(parent)
            .map_err(|error| ObjectError::new(ObjectErrorKind::UnsafePath, error.message))?;
        let final_path = safe_parent.join(basename);
        match fs::symlink_metadata(&final_path) {
            Ok(_) => {
                return Err(ObjectError::new(
                    ObjectErrorKind::AlreadyExists,
                    "materialization destination already exists",
                ))
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(ObjectError::io("inspect destination", error)),
        }

        let stage_path = safe_parent.join(temp_name("checkout"));
        create_private_directory(&stage_path)?;
        let mut guard = DirectoryCleanup(Some(stage_path.clone()));

        // A stage is owned by the current process. Local malicious directory
        // replacement races remain out of scope pending handle-based APIs.
        for entry in &entries {
            validate_path(&entry.path)?;
            let bytes = self.get_blob(&entry.blob)?;
            let components: Vec<&str> = entry.path.split('/').collect();
            let mut dir = stage_path.clone();
            for component in components.iter().take(components.len() - 1) {
                dir.push(component);
                match fs::create_dir(&dir) {
                    Ok(()) => {}
                    Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
                    Err(error) => {
                        return Err(ObjectError::io("create materialized directory", error))
                    }
                }
                let metadata = metadata(&dir)?;
                if is_link_like(&metadata) || !metadata.is_dir() {
                    return Err(unsafe_path());
                }
            }
            let target = dir.join(components[components.len() - 1]);
            let mut file = create_private_file(&target)?;
            file.write_all(&bytes)
                .map_err(|error| ObjectError::io("write materialized bytes", error))?;
            file.sync_all()
                .map_err(|error| ObjectError::io("sync materialized file", error))?;
            drop(file);

            #[cfg(unix)]
            if entry.executable {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&target, fs::Permissions::from_mode(0o700))
                    .map_err(|error| ObjectError::io("mark executable", error))?;
                File::open(&target)
                    .and_then(|opened| opened.sync_all())
                    .map_err(|error| ObjectError::io("sync executable mode", error))?;
            }
        }

        sync_directory_tree(&stage_path)?;
        // Compare again before rename, but do not claim race-free no-replace
        // against a separate malicious same-user process.
        if fs::symlink_metadata(&final_path).is_ok() {
            return Err(ObjectError::new(
                ObjectErrorKind::AlreadyExists,
                "materialization destination changed during write",
            ));
        }
        publish_directory_noreplace(&stage_path, &final_path)?;
        guard.0 = None;
        sync_directory(&safe_parent)?;
        Ok(())
    }

    pub(crate) fn put_object(
        &self,
        kind: ObjectKind,
        bytes: &[u8],
    ) -> Result<ObjectId, ObjectError> {
        let limit = object_limit(kind);
        if bytes.len() > limit {
            return Err(ObjectError::new(
                ObjectErrorKind::TooLarge,
                "object exceeds configured maximum length",
            ));
        }
        let id = ObjectId::for_content(kind, bytes);
        let path = self.object_path(&id, true)?;
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                self.check_existing(&id, bytes)?;
                return Ok(id);
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(ObjectError::io("inspect existing object", error)),
        }

        let parent = path.parent().ok_or_else(unsafe_path)?;
        let staging = parent.join(temp_name("object"));
        // Only own/remove a stage after exclusive creation succeeds. A
        // collided name must never cause deletion of somebody else's file.
        let mut file = create_private_file(&staging)?;
        let mut cleanup = FileCleanup(Some(staging.clone()));
        file.write_all(bytes)
            .map_err(|error| ObjectError::io("write staging object", error))?;
        file.sync_all()
            .map_err(|error| ObjectError::io("sync staging object", error))?;
        drop(file);

        // Atomic no-overwrite publication on the same filesystem. A normal
        // rename may replace an existing object and is deliberately not used.
        match fs::hard_link(&staging, &path) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                self.check_existing(&id, bytes)?;
            }
            Err(error) => return Err(ObjectError::io("publish immutable object", error)),
        }
        fs::remove_file(&staging)
            .map_err(|error| ObjectError::io("remove temporary object", error))?;
        cleanup.0 = None;
        sync_directory(parent)?;
        Ok(id)
    }

    fn check_existing(&self, id: &ObjectId, expected: &[u8]) -> Result<(), ObjectError> {
        let existing = self.get_object(id, id.kind())?;
        if existing != expected {
            return Err(ObjectError::new(
                ObjectErrorKind::Corrupt,
                "existing digest object differs from supplied bytes",
            ));
        }
        Ok(())
    }

    pub(crate) fn get_object(
        &self,
        id: &ObjectId,
        required_kind: ObjectKind,
    ) -> Result<Vec<u8>, ObjectError> {
        if id.kind() != required_kind {
            return Err(ObjectError::new(
                ObjectErrorKind::WrongType,
                "object kind does not match requested API",
            ));
        }
        let location = self.object_path(id, false)?;
        let file_metadata = metadata(&location)?;
        if is_link_like(&file_metadata) {
            return Err(unsafe_path());
        }
        if !file_metadata.is_file() || file_metadata.len() > object_limit(required_kind) as u64 {
            return Err(ObjectError::new(
                ObjectErrorKind::Corrupt,
                "stored object is not a bounded regular file",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if file_metadata.permissions().mode() & 0o077 != 0 {
                return Err(unsafe_path());
            }
        }
        #[cfg(windows)]
        crate::windows_security::verify_private_acl(&location).map_err(|_| unsafe_path())?;
        let bytes = read_bounded(&location, object_limit(required_kind), true)?;
        if &ObjectId::for_content(required_kind, &bytes) != id {
            return Err(ObjectError::new(
                ObjectErrorKind::Corrupt,
                "stored object digest mismatch",
            ));
        }
        Ok(bytes)
    }

    fn object_path(&self, id: &ObjectId, create: bool) -> Result<PathBuf, ObjectError> {
        // Re-verify marker; an invalidated store never accepts further writes.
        inspect_repository(&self.root)
            .map_err(|error| ObjectError::new(ObjectErrorKind::InvalidStore, error.message))?;
        let metadata_dir = child_directory(&self.root, ".openscion", false)?;
        let base = child_directory(&metadata_dir, "objects", create)?;
        let kind_dir = child_directory(&base, id.kind().tag(), create)?;
        let hex = id.to_string();
        let digest = &hex[3..];
        let shard = child_directory(&kind_dir, &digest[..2], create)?;
        Ok(shard.join(digest))
    }
}

struct FileCleanup(Option<PathBuf>);

impl Drop for FileCleanup {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            fs::remove_file(path).ok();
        }
    }
}

struct DirectoryCleanup(Option<PathBuf>);

impl Drop for DirectoryCleanup {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            fs::remove_dir_all(path).ok();
        }
    }
}

// Atomic destination-existence enforcement is essential. A pre-check
// followed by std::fs::rename() can overwrite an empty directory when
// another local process races publication. Unsupported platforms fail closed.
#[cfg(target_os = "linux")]
fn publish_directory_noreplace(source: &Path, target: &Path) -> Result<(), ObjectError> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let src = CString::new(source.as_os_str().as_bytes()).map_err(|_| unsafe_path())?;
    let dst = CString::new(target.as_os_str().as_bytes()).map_err(|_| unsafe_path())?;
    // SAFETY: CString arguments are terminated and live across the call.
    // This syscall does not dereference Rust-managed memory after returning.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            src.as_ptr(),
            libc::AT_FDCWD,
            dst.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    // Linux renameat2(RENAME_NOREPLACE) reports EEXIST for a real
    // destination collision. Do not interpret unrelated errno values
    // (EIO=5, e.g. media failure) as a successful conflict observation.
    if error.kind() == ErrorKind::AlreadyExists {
        if let Ok(attributes) = fs::symlink_metadata(target) {
            if is_link_like(&attributes) {
                return Err(unsafe_path());
            }
            return Err(ObjectError::new(
                ObjectErrorKind::AlreadyExists,
                "materialization destination already exists",
            ));
        }
    }
    Err(ObjectError::io(
        "publish directory without overwrite",
        error,
    ))
}

#[cfg(windows)]
fn publish_directory_noreplace(source: &Path, target: &Path) -> Result<(), ObjectError> {
    #[link(name = "kernel32")]
    extern "system" {
        fn MoveFileW(existing_name: *const u16, new_name: *const u16) -> i32;
    }
    // Reject embedded NULs and overlong paths before passing them into Win32.
    // A truncated path could otherwise publish under an unintended name.
    let source_wide = crate::windows_security::path_wide(source).map_err(|_| unsafe_path())?;
    let target_wide = crate::windows_security::path_wide(target).map_err(|_| unsafe_path())?;
    // SAFETY: Both terminated UTF-16 buffers remain allocated throughout
    // the synchronous Win32 call. MoveFileW refuses existing destinations.
    let result = unsafe { MoveFileW(source_wide.as_ptr(), target_wide.as_ptr()) };
    if result != 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    // MoveFileW may report ERROR_ACCESS_DENIED for an existing directory,
    // or ERROR_FILE_EXISTS/ALREADY_EXISTS. Confirm a real target exists
    // before translating these errors; never hide an unrelated ACL failure.
    if error.kind() == ErrorKind::AlreadyExists
        || matches!(error.raw_os_error(), Some(5 | 80 | 183))
    {
        if let Ok(attributes) = fs::symlink_metadata(target) {
            if is_link_like(&attributes) {
                return Err(unsafe_path());
            }
            return Err(ObjectError::new(
                ObjectErrorKind::AlreadyExists,
                "materialization destination already exists",
            ));
        }
    }
    Err(ObjectError::io(
        "publish directory without overwrite",
        error,
    ))
}

#[cfg(not(any(target_os = "linux", windows)))]
fn publish_directory_noreplace(_source: &Path, _target: &Path) -> Result<(), ObjectError> {
    Err(ObjectError::new(
        ObjectErrorKind::Io,
        "atomic no-overwrite directory publication unavailable on this platform",
    ))
}

fn object_limit(kind: ObjectKind) -> usize {
    match kind {
        ObjectKind::Blob => MAX_BLOB_BYTES,
        ObjectKind::Snapshot => MAX_SNAPSHOT_BYTES,
        ObjectKind::Proposal => super::changes::MAX_PROPOSAL_BYTES,
        ObjectKind::Revision => super::changes::MAX_REVISION_BYTES,
    }
}

fn temp_name(namespace: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    format!(
        ".openscion-{namespace}-{}-{nanos}-{}",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    )
}

fn child_directory(parent: &Path, name: &str, create: bool) -> Result<PathBuf, ObjectError> {
    let child = parent.join(name);
    if create {
        match create_private_directory(&child) {
            Ok(()) => sync_directory(parent)?,
            Err(error) if error.kind == ObjectErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    let attributes = metadata(&child)?;
    if is_link_like(&attributes) || !attributes.is_dir() {
        return Err(unsafe_path());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if attributes.permissions().mode() & 0o077 != 0 {
            return Err(unsafe_path());
        }
    }
    #[cfg(windows)]
    crate::windows_security::verify_private_acl(&child).map_err(|_| unsafe_path())?;
    Ok(child)
}

fn create_private_directory(path: &Path) -> Result<(), ObjectError> {
    #[cfg(windows)]
    let result = crate::windows_security::create_private_directory(path);
    #[cfg(not(windows))]
    let result = {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(path)
    };
    result.map_err(|error| {
        if error.kind() == ErrorKind::AlreadyExists {
            ObjectError::new(ObjectErrorKind::AlreadyExists, "directory already exists")
        } else {
            ObjectError::io("create private directory", error)
        }
    })
}

fn create_private_file(path: &Path) -> Result<File, ObjectError> {
    #[cfg(windows)]
    let result = crate::windows_security::create_private_file(path);
    #[cfg(not(windows))]
    let result = {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        opts.open(path)
    };
    result.map_err(|error| ObjectError::io("create private exclusive file", error))
}

fn metadata(path: &Path) -> Result<fs::Metadata, ObjectError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata),
        Err(error) if error.kind() == ErrorKind::NotFound => Err(ObjectError::new(
            ObjectErrorKind::Missing,
            "object or path does not exist",
        )),
        Err(error) => Err(ObjectError::io("inspect object or path", error)),
    }
}

fn read_bounded(path: &Path, limit: usize, stored: bool) -> Result<Vec<u8>, ObjectError> {
    let file = File::open(path).map_err(|error| ObjectError::io("open bounded file", error))?;
    let mut out = Vec::new();
    file.take((limit as u64) + 1)
        .read_to_end(&mut out)
        .map_err(|error| ObjectError::io("read bounded file", error))?;
    if out.len() > limit {
        let kind = if stored {
            ObjectErrorKind::Corrupt
        } else {
            ObjectErrorKind::TooLarge
        };
        return Err(ObjectError::new(kind, "bounded file exceeds limit"));
    }
    Ok(out)
}

/// Flush directory entries bottom-up, so a successfully published tree
/// does not rely on unsynchronized nested directory metadata on Linux.
fn sync_directory_tree(directory: &Path) -> Result<(), ObjectError> {
    let children = fs::read_dir(directory)
        .map_err(|error| ObjectError::io("enumerate staged directory", error))?;
    for child in children {
        let child = child.map_err(|error| ObjectError::io("inspect staged directory", error))?;
        let attr = child
            .file_type()
            .map_err(|error| ObjectError::io("inspect staged entry", error))?;
        if attr.is_symlink() {
            return Err(unsafe_path());
        }
        if attr.is_dir() {
            sync_directory_tree(&child.path())?;
        }
    }
    sync_directory(directory)
}

fn sync_directory(path: &Path) -> Result<(), ObjectError> {
    #[cfg(target_os = "linux")]
    {
        File::open(path)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| ObjectError::io("fsync directory", error))?;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = path; // Directory flush guarantees are platform-specific.
    Ok(())
}

fn unsafe_path() -> ObjectError {
    ObjectError::new(
        ObjectErrorKind::UnsafePath,
        "object path is unsafe or contains a link",
    )
}
