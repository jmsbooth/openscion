//! Local repository bootstrap. Revision storage and promotion are not implemented.
//!
//! No agent credentials, approval proofs, or provenance can be established by
//! these methods. A valid format marker indicates *only* that the local
//! directory was initialized with a recognized version.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Component, Path, PathBuf};

/// Canonical local format marker; the trailing newline is part of the format.
pub const FORMAT_MARKER: &[u8] = b"openscion.local-store/1\n";

/// Stable error category independent of operating-system error strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    UnsafePath,
    NotDirectory,
    NotInitialized,
    AlreadyInitialized,
    InvalidStore,
    Io,
}

impl ErrorCode {
    /// Stable code for scripts; never contains caller-controlled input.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsafePath => "E_UNSAFE_PATH",
            Self::NotDirectory => "E_NOT_DIRECTORY",
            Self::NotInitialized => "E_NOT_INITIALIZED",
            Self::AlreadyInitialized => "E_ALREADY_INITIALIZED",
            Self::InvalidStore => "E_INVALID_STORE",
            Self::Io => "E_IO",
        }
    }

    /// CLI exit status. Two is reserved for command usage errors.
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::UnsafePath | Self::NotDirectory => 3,
            Self::NotInitialized => 4,
            Self::AlreadyInitialized => 5,
            Self::InvalidStore => 6,
            Self::Io => 7,
        }
    }
}

#[derive(Debug)]
pub struct StoreError {
    pub code: ErrorCode,
    pub message: String,
}

impl StoreError {
    fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    fn io(context: &'static str, error: std::io::Error) -> Self {
        Self::new(ErrorCode::Io, format!("{context}: {error}"))
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for StoreError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepositoryState {
    /// The local store contains no revision or channel head.
    Unborn,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryInfo {
    pub root: PathBuf,
    pub state: RepositoryState,
}

/// Reject both symbolic links and Windows junction/reparse points.
///
/// A reparse point can appear directory-like without being classified by
/// FileType::is_symlink on Windows.
fn is_link_like(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    false
}

/// Reject lexical traversal and symlinks in every existing path component.
///
/// This checks the namespace at the time of inspection. A hostile local
/// actor with concurrent write access could replace directories afterward;
/// M1 does not claim race-free containment against that attacker.
fn validate_directory(path: &Path) -> Result<PathBuf, StoreError> {
    if path.as_os_str().is_empty() {
        return Err(StoreError::new(ErrorCode::UnsafePath, "empty repository path"));
    }
    if path.components().any(|part| part == Component::ParentDir) {
        return Err(StoreError::new(
            ErrorCode::UnsafePath,
            "parent traversal in repository path is forbidden",
        ));
    }

    // Windows drive-relative paths (for example "C:relative") resolve
    // against drive-specific process state and must not be accepted.
    if !path.is_absolute()
        && matches!(path.components().next(), Some(Component::Prefix(_)))
    {
        return Err(StoreError::new(
            ErrorCode::UnsafePath,
            "drive-relative repository paths are forbidden",
        ));
    }

    let full = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| StoreError::io("read current directory", error))?
            .join(path)
    };

    let mut candidate = PathBuf::new();
    for component in full.components() {
        match component {
            Component::ParentDir => {
                return Err(StoreError::new(
                    ErrorCode::UnsafePath,
                    "parent traversal in repository path is forbidden",
                ))
            }
            Component::CurDir => continue,
            // On Windows, a bare drive prefix is not an inspectable directory.
            Component::Prefix(prefix) => {
                candidate.push(prefix.as_os_str());
                continue;
            }
            Component::RootDir | Component::Normal(_) => candidate.push(component.as_os_str()),
        }

        let attributes = match fs::symlink_metadata(&candidate) {
            Ok(attributes) => attributes,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Err(StoreError::new(
                    ErrorCode::NotDirectory,
                    "repository directory must already exist",
                ))
            }
            Err(error) => return Err(StoreError::io("inspect repository path", error)),
        };
        if is_link_like(&attributes) {
            return Err(StoreError::new(
                ErrorCode::UnsafePath,
                "repository path contains a symbolic link",
            ));
        }
        if !attributes.is_dir() {
            return Err(StoreError::new(
                ErrorCode::NotDirectory,
                "repository target or ancestor is not a directory",
            ));
        }
    }

    Ok(full)
}

/// Create an empty local store. It is not a source control revision.
///
/// Directory creation is exclusive; a failed or interrupted marker write
/// leaves an invalid store that status refuses to accept. We intentionally
/// never overwrite or auto-repair metadata in this increment.
pub fn initialize_repository(path: &Path) -> Result<RepositoryInfo, StoreError> {
    let root = validate_directory(path)?;
    let metadata_dir = root.join(".openscion");

    let mut builder = fs::DirBuilder::new();
    builder.recursive(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }

    if let Err(error) = builder.create(&metadata_dir) {
        if error.kind() == ErrorKind::AlreadyExists {
            if let Ok(attributes) = fs::symlink_metadata(&metadata_dir) {
                if is_link_like(&attributes) {
                    return Err(StoreError::new(
                        ErrorCode::UnsafePath,
                        "repository metadata path is a symbolic link",
                    ));
                }
            }
            return Err(StoreError::new(
                ErrorCode::AlreadyInitialized,
                "repository metadata already exists; refusing to overwrite",
            ));
        }
        return Err(StoreError::io("create metadata directory", error));
    }

    let temporary_marker = metadata_dir.join("format.pending");
    let marker = metadata_dir.join("format");
    let mut marker_options = OpenOptions::new();
    marker_options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        marker_options.mode(0o600);
    }
    let mut stream = marker_options
        .open(&temporary_marker)
        .map_err(|error| StoreError::io("create format marker staging file", error))?;
    stream
        .write_all(FORMAT_MARKER)
        .map_err(|error| StoreError::io("write format marker", error))?;
    stream
        .sync_all()
        .map_err(|error| StoreError::io("synchronize format marker", error))?;
    drop(stream);

    // A hard link publishes the marker without replacing an existing name.
    // Rename can overwrite another writer's format file on Unix.
    fs::hard_link(&temporary_marker, &marker)
        .map_err(|error| StoreError::io("publish exclusive format marker", error))?;
    fs::remove_file(&temporary_marker)
        .map_err(|error| StoreError::io("remove completed marker staging file", error))?;

    // fsync of directories is supported on Linux; unsupported platforms
    // should not be misrepresented as having the same crash durability.
    #[cfg(target_os = "linux")]
    {
        File::open(&metadata_dir)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| StoreError::io("synchronize metadata directory", error))?;
        File::open(&root)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| StoreError::io("synchronize repository directory", error))?;
    }

    inspect_repository(&root)
}

/// Check recognized marker bytes and fail closed for corruption or partial init.
///
/// This validates an *empty local store format only*. It does not verify
/// revisions, content, approvals, or cryptographic provenance.
pub fn inspect_repository(path: &Path) -> Result<RepositoryInfo, StoreError> {
    let root = validate_directory(path)?;
    let metadata_dir = root.join(".openscion");
    let metadata = match fs::symlink_metadata(&metadata_dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Err(StoreError::new(
                ErrorCode::NotInitialized,
                "no OpenScion metadata directory",
            ))
        }
        Err(error) => return Err(StoreError::io("inspect metadata directory", error)),
    };

    if is_link_like(&metadata) {
        return Err(StoreError::new(
            ErrorCode::UnsafePath,
            "metadata directory is a symbolic link",
        ));
    }
    if !metadata.is_dir() {
        return Err(StoreError::new(
            ErrorCode::InvalidStore,
            "metadata path is not a directory",
        ));
    }
    // Untrusted agents must not gain access simply because a local user
    // accidentally changed metadata permissions. Do not auto-chmod.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(StoreError::new(
                ErrorCode::InvalidStore,
                "metadata directory must be owner-only",
            ));
        }
    }

    let marker = metadata_dir.join("format");
    let marker_metadata = match fs::symlink_metadata(&marker) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Err(StoreError::new(
                ErrorCode::InvalidStore,
                "partial or incomplete metadata: format marker missing",
            ))
        }
        Err(error) => return Err(StoreError::io("inspect format marker", error)),
    };
    if is_link_like(&marker_metadata) {
        return Err(StoreError::new(
            ErrorCode::UnsafePath,
            "format marker is a symbolic link",
        ));
    }
    if !marker_metadata.is_file() || marker_metadata.len() > 64 {
        return Err(StoreError::new(
            ErrorCode::InvalidStore,
            "format marker is invalid or oversized",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if marker_metadata.permissions().mode() & 0o077 != 0 {
            return Err(StoreError::new(
                ErrorCode::InvalidStore,
                "format marker must be owner-only",
            ));
        }
    }

    // Limit reads even if a malicious writer expands the file after stat.
    let mut bytes = Vec::new();
    File::open(&marker)
        .map_err(|error| StoreError::io("open format marker", error))?
        .take(65)
        .read_to_end(&mut bytes)
        .map_err(|error| StoreError::io("read format marker", error))?;
    if bytes.as_slice() != FORMAT_MARKER {
        return Err(StoreError::new(
            ErrorCode::InvalidStore,
            "unsupported or corrupted format marker",
        ));
    }

    Ok(RepositoryInfo {
        root,
        state: RepositoryState::Unborn,
    })
}
