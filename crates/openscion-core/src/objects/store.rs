use super::identity::{ObjectId, ObjectKind};
use super::safe_path::validate_path;
use super::snapshot::{Snapshot, SnapshotEntry};
use super::{ObjectError, ObjectErrorKind, MAX_BLOB_BYTES, MAX_SNAPSHOT_BYTES};
use crate::{inspect_repository, is_link_like, validate_directory, ErrorCode};
use std::fs::{self, File, OpenOptions};
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
        for entry in snapshot.entries() {
            // Never accept an unverified or missing referenced blob.
            self.get_blob(&entry.blob)?;
        }
        self.put_object(ObjectKind::Snapshot, &snapshot.encode())
    }

    pub fn get_snapshot(&self, id: &ObjectId) -> Result<Vec<SnapshotEntry>, ObjectError> {
        let bytes = self.get_object(id, ObjectKind::Snapshot)?;
        let entries = Snapshot::decode(&bytes)?.entries().to_vec();
        for entry in &entries {
            self.get_blob(&entry.blob)?;
        }
        Ok(entries)
    }

    /// Import a source file from inside the repository using a portable
    /// relative name. Nonregular files and symlinks are never dereferenced.
    pub fn put_repo_file(&self, relative: &str) -> Result<ObjectId, ObjectError> {
        let bytes = self.read_repo_file(relative, MAX_BLOB_BYTES)?;
        self.put_blob(&bytes)
    }

    /// Bounded repo-relative file read, used for file and manifest ingestion.
    pub fn read_repo_file(
        &self,
        relative: &str,
        limit: usize,
    ) -> Result<Vec<u8>, ObjectError> {
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
            if final_component && !metadata.is_file()
                || !final_component && !metadata.is_dir()
            {
                return Err(unsafe_path());
            }
        }
        read_bounded(&current, limit, false)
    }

    /// Materialize a full verified snapshot into a *nonexistent* directory.
    ///
    /// No committed revisions exist yet. This operation only exposes file
    /// bytes from a known snapshot in a disposable local workspace.
    pub fn materialize(&self, snapshot_id: &ObjectId, destination: &Path) -> Result<(), ObjectError> {
        let entries = self.get_snapshot(snapshot_id)?;
        if destination
            .components()
            .any(|component| component == std::path::Component::ParentDir)
        {
            return Err(unsafe_path());
        }
        let basename = destination.file_name().ok_or_else(unsafe_path)?;
        if basename == "." || basename == ".." {
            return Err(unsafe_path());
        }
        let parent = destination.parent().filter(|p| !p.as_os_str().is_empty())
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
                    Err(error) => return Err(ObjectError::io("create materialized directory", error)),
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
            }
        }

        sync_directory(&stage_path)?;
        // Compare again before rename, but do not claim race-free no-replace
        // against a separate malicious same-user process.
        if fs::symlink_metadata(&final_path).is_ok() {
            return Err(ObjectError::new(
                ObjectErrorKind::AlreadyExists,
                "materialization destination changed during write",
            ));
        }
        fs::rename(&stage_path, &final_path)
            .map_err(|error| ObjectError::io("publish materialized directory", error))?;
        guard.0 = None;
        sync_directory(&safe_parent)?;
        Ok(())
    }

    fn put_object(&self, kind: ObjectKind, bytes: &[u8]) -> Result<ObjectId, ObjectError> {
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
        let mut cleanup = FileCleanup(staging.clone());
        let mut file = create_private_file(&staging)?;
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

    fn get_object(
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

struct FileCleanup(PathBuf);

impl Drop for FileCleanup {
    fn drop(&mut self) {
        fs::remove_file(&self.0).ok();
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

fn object_limit(kind: ObjectKind) -> usize {
    match kind {
        ObjectKind::Blob => MAX_BLOB_BYTES,
        ObjectKind::Snapshot => MAX_SNAPSHOT_BYTES,
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
    Ok(child)
}

fn create_private_directory(path: &Path) -> Result<(), ObjectError> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(|error| {
        if error.kind() == ErrorKind::AlreadyExists {
            ObjectError::new(ObjectErrorKind::AlreadyExists, "directory already exists")
        } else {
            ObjectError::io("create directory", error)
        }
    })
}

fn create_private_file(path: &Path) -> Result<File, ObjectError> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path).map_err(|error| ObjectError::io("create exclusive file", error))
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
    ObjectError::new(ObjectErrorKind::UnsafePath, "object path is unsafe or contains a link")
}
