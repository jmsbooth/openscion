use openscion_core::{
    initialize_repository, inspect_repository, ErrorCode, RepositoryState, FORMAT_MARKER,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NONCE: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "openscion-core-{}-{}-{}",
            std::process::id(),
            unique,
            NONCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("create isolated fixture");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).ok();
    }
}

#[test]
fn init_creates_exact_format_marker_and_unborn_state() {
    let root = Fixture::new();
    let info = initialize_repository(root.path()).unwrap();
    assert_eq!(info.state, RepositoryState::Unborn);
    assert_eq!(
        fs::read(root.path().join(".openscion/format")).unwrap(),
        FORMAT_MARKER
    );
    assert_eq!(
        inspect_repository(root.path()).unwrap().state,
        RepositoryState::Unborn
    );
}

#[test]
fn reinitialization_fails_and_never_overwrites_marker() {
    let root = Fixture::new();
    initialize_repository(root.path()).unwrap();
    let before = fs::read(root.path().join(".openscion/format")).unwrap();
    let err = initialize_repository(root.path()).unwrap_err();
    assert_eq!(err.code, ErrorCode::AlreadyInitialized);
    assert_eq!(
        fs::read(root.path().join(".openscion/format")).unwrap(),
        before
    );
}

#[test]
fn inspect_missing_metadata_fails_closed() {
    let root = Fixture::new();
    assert_eq!(
        inspect_repository(root.path()).unwrap_err().code,
        ErrorCode::NotInitialized
    );
}

#[test]
fn inspect_rejects_tampered_and_oversized_markers() {
    let root = Fixture::new();
    initialize_repository(root.path()).unwrap();
    let marker = root.path().join(".openscion/format");
    fs::write(&marker, b"malicious-v2\n").unwrap();
    assert_eq!(
        inspect_repository(root.path()).unwrap_err().code,
        ErrorCode::InvalidStore
    );
    fs::write(&marker, vec![b'x'; 1024]).unwrap();
    assert_eq!(
        inspect_repository(root.path()).unwrap_err().code,
        ErrorCode::InvalidStore
    );
}

#[test]
fn partial_metadata_is_never_reported_initialized() {
    let root = Fixture::new();
    fs::create_dir(root.path().join(".openscion")).unwrap();
    assert_eq!(
        inspect_repository(root.path()).unwrap_err().code,
        ErrorCode::InvalidStore
    );
    assert_eq!(
        initialize_repository(root.path()).unwrap_err().code,
        ErrorCode::AlreadyInitialized
    );
}

#[test]
fn init_rejects_file_target_and_nonexistent_root() {
    let root = Fixture::new();
    let file = root.path().join("file");
    fs::write(&file, "not-a-directory").unwrap();
    assert_eq!(
        initialize_repository(&file).unwrap_err().code,
        ErrorCode::NotDirectory
    );
    assert_eq!(
        initialize_repository(&root.path().join("absent"))
            .unwrap_err()
            .code,
        ErrorCode::NotDirectory
    );
}

#[test]
fn init_rejects_parent_traversal_before_any_side_effect() {
    let root = Fixture::new();
    let bad = root.path().join("child/../target");
    assert_eq!(
        initialize_repository(&bad).unwrap_err().code,
        ErrorCode::UnsafePath
    );
    assert!(!root.path().join("target").exists());
}

#[cfg(unix)]
#[test]
fn init_rejects_symlink_root_and_ancestor() {
    use std::os::unix::fs::symlink;
    let root = Fixture::new();
    let nested = root.path().join("real");
    fs::create_dir(&nested).unwrap();
    symlink(&nested, root.path().join("alias")).unwrap();
    let link = root.path().join("alias");
    assert_eq!(
        initialize_repository(&link).unwrap_err().code,
        ErrorCode::UnsafePath
    );
    assert_eq!(
        initialize_repository(&link.join("child")).unwrap_err().code,
        ErrorCode::UnsafePath
    );
    assert!(!nested.join(".openscion").exists());
}

#[cfg(unix)]
#[test]
fn inspect_rejects_symlink_metadata_and_marker() {
    use std::os::unix::fs::symlink;
    let root = Fixture::new();
    let destination = root.path().join("outside");
    fs::create_dir(&destination).unwrap();
    symlink(&destination, root.path().join(".openscion")).unwrap();
    assert_eq!(
        inspect_repository(root.path()).unwrap_err().code,
        ErrorCode::UnsafePath
    );
    fs::remove_file(root.path().join(".openscion")).unwrap();
    initialize_repository(root.path()).unwrap();
    let marker = root.path().join(".openscion/format");
    fs::remove_file(&marker).unwrap();
    let alternate = root.path().join("altered");
    fs::write(&alternate, FORMAT_MARKER).unwrap();
    symlink(&alternate, &marker).unwrap();
    assert_eq!(
        inspect_repository(root.path()).unwrap_err().code,
        ErrorCode::UnsafePath
    );
}

#[test]
fn empty_repository_path_is_rejected() {
    assert_eq!(
        initialize_repository(Path::new("")).unwrap_err().code,
        ErrorCode::UnsafePath
    );
}

#[cfg(unix)]
#[test]
fn metadata_directory_has_owner_only_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let root = Fixture::new();
    initialize_repository(root.path()).unwrap();
    let metadata_path = root.path().join(".openscion");
    let permissions = fs::metadata(&metadata_path).unwrap().permissions().mode();
    assert_eq!(permissions & 0o077, 0, "metadata must not grant group/other access");
    assert!(!metadata_path.join("format.pending").exists());
}
