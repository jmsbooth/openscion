use openscion_core::initialize_repository;
use openscion_core::objects::{
    ObjectErrorKind, ObjectId, ObjectKind, ObjectStore, Snapshot, SnapshotEntry, MAX_BLOB_BYTES,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let root = std::env::temp_dir().join(format!(
            "openscion-cas-{}-{}-{}",
            std::process::id(),
            now,
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn store(&self) -> ObjectStore {
        initialize_repository(self.path()).unwrap();
        ObjectStore::open(self.path()).unwrap()
    }

    fn object_path(&self, id: &ObjectId) -> PathBuf {
        let text = id.to_string();
        let (kind, digest) = text.split_once('_').unwrap();
        self.path()
            .join(".openscion/objects")
            .join(kind)
            .join(&digest[..2])
            .join(digest)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).ok();
    }
}

fn entry(path: &str, blob: &ObjectId, executable: bool) -> SnapshotEntry {
    SnapshotEntry {
        path: path.to_owned(),
        blob: blob.clone(),
        executable,
    }
}

#[test]
fn known_sha256_test_vectors_are_stable_and_domain_separated() {
    assert_eq!(
        ObjectId::for_content(ObjectKind::Blob, b"").to_string(),
        "b1_ad9d112b8c5063b4f394c2c16c6c5ecb42fa36453f81d02d5029f7d4049185bc"
    );
    assert_eq!(
        ObjectId::for_content(ObjectKind::Blob, b"abc").to_string(),
        "b1_6c306925773a9a4fa79e7a6369bbe233af1b1d93aaa1af262ecacbc69d3e600b"
    );
    let bytes = b"same contents";
    assert_ne!(
        ObjectId::for_content(ObjectKind::Blob, bytes),
        ObjectId::for_content(ObjectKind::Snapshot, bytes)
    );
}

#[test]
fn blob_store_is_deterministic_and_returns_original_bytes() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let payload = b"let main = \"hello\";\n";
    let first = store.put_blob(payload).unwrap();
    let second = store.put_blob(payload).unwrap();
    assert_eq!(first, second);
    assert_eq!(store.get_blob(&first).unwrap(), payload);
    assert_eq!(fs::read(fixture.object_path(&first)).unwrap(), payload);
    assert!(!fixture.object_path(&first).with_extension("pending").exists());
    assert_ne!(store.put_blob(b"other").unwrap(), first);
}

#[test]
fn corrupt_stored_bytes_are_detected_and_not_replaced() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let original = b"trusted";
    let id = store.put_blob(original).unwrap();
    let path = fixture.object_path(&id);
    fs::write(&path, b"tainted").unwrap();
    assert_eq!(store.get_blob(&id).unwrap_err().kind, ObjectErrorKind::Corrupt);
    assert_eq!(store.put_blob(original).unwrap_err().kind, ObjectErrorKind::Corrupt);
    assert_eq!(fs::read(path).unwrap(), b"tainted");
}

#[test]
fn strict_id_parsing_and_type_enforcement() {
    let blob = ObjectId::for_content(ObjectKind::Blob, b"x");
    let text = blob.to_string();
    assert_eq!(ObjectId::parse(&text).unwrap(), blob);
    for invalid in [
        "",
        "b1_deadbeef",
        "b1_000000000000000000000000000000000000000000000000000000000000000G",
        "z1_0000000000000000000000000000000000000000000000000000000000000000",
        "b1_000000000000000000000000000000000000000000000000000000000000000A",
        "b1_0000000000000000000000000000000000000000000000000000000000000000/",
    ] {
        assert_eq!(
            ObjectId::parse(invalid).unwrap_err().kind,
            ObjectErrorKind::InvalidId,
            "unexpected acceptance: {invalid:?}"
        );
    }
    let fixture = Fixture::new();
    let store = fixture.store();
    let id = store.put_blob(b"x").unwrap();
    let wrong_type = ObjectId::parse(&format!("s1_{}", &id.to_string()[3..])).unwrap();
    assert_eq!(
        store.get_blob(&wrong_type).unwrap_err().kind,
        ObjectErrorKind::WrongType
    );
}

#[test]
fn oversized_blob_is_refused_without_publishing_objects() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let too_large = vec![0x77; MAX_BLOB_BYTES + 1];
    assert_eq!(
        store.put_blob(&too_large).unwrap_err().kind,
        ObjectErrorKind::TooLarge
    );
    assert!(!fixture.path().join(".openscion/objects").exists());
}

#[test]
fn snapshot_encoding_is_order_independent_and_has_golden_empty_id() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let a = store.put_blob(b"A").unwrap();
    let b = store.put_blob(b"B").unwrap();
    let first = vec![entry("src/z.rs", &a, false), entry("src/a.rs", &b, true)];
    let second = vec![entry("src/a.rs", &b, true), entry("src/z.rs", &a, false)];
    let id1 = store.put_snapshot(&first).unwrap();
    let id2 = store.put_snapshot(&second).unwrap();
    assert_eq!(id1, id2);
    assert_eq!(store.get_snapshot(&id1).unwrap(), second);
    let bytes = fs::read(fixture.object_path(&id1)).unwrap();
    assert_eq!(Snapshot::decode(&bytes).unwrap().entries(), second.as_slice());

    let empty = store.put_snapshot(&[]).unwrap();
    assert_eq!(
        empty.to_string(),
        "s1_0e226daee94758aaceff2b27f8033e9d3eb3462026581d79ea3d4d2bd8e17a65"
    );
}

#[test]
fn invalid_paths_and_case_or_prefix_collisions_are_refused() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let blob = store.put_blob(b"x").unwrap();
    for path in [
        "",
        "../secret",
        "/absolute",
        "a//b",
        "a/./b",
        "a/../b",
        "a/",
        ".openscion/format",
        ".git/config",
        "vendor/.git/config",
        "source/.openscion/format",
        "nested/.GiT/hooks/post-commit",
        "src\\win.rs",
        "a:evil",
        "con",
        "Con.txt",
        "aux.json",
        "COM1",
        "LPT9.log",
        "invalid file",
        "caf\u{e9}.rs",
        "trailing.",
    ] {
        assert_eq!(
            store.put_snapshot(&[entry(path, &blob, false)])
                .unwrap_err()
                .kind,
            ObjectErrorKind::UnsafePath,
            "{path}"
        );
    }
    for paths in [("ReadMe.md", "README.md"), ("src", "src/main.rs"), ("src/a", "SRC/A")] {
        let entries = [entry(paths.0, &blob, false), entry(paths.1, &blob, false)];
        assert_eq!(
            store.put_snapshot(&entries).unwrap_err().kind,
            ObjectErrorKind::InvalidSnapshot
        );
    }
}

#[test]
fn missing_or_damaged_blob_prevents_snapshot_publication_or_reads() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let missing = ObjectId::for_content(ObjectKind::Blob, b"not-uploaded");
    assert_eq!(
        store.put_snapshot(&[entry("a.txt", &missing, false)])
            .unwrap_err().kind,
        ObjectErrorKind::Missing
    );
    let blob = store.put_blob(b"original").unwrap();
    let snapshot = store.put_snapshot(&[entry("a.txt", &blob, false)]).unwrap();
    fs::write(fixture.object_path(&blob), b"corrupted").unwrap();
    assert_eq!(
        store.get_snapshot(&snapshot).unwrap_err().kind,
        ObjectErrorKind::Corrupt
    );
}

#[test]
fn malformed_snapshot_bytes_are_refused() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let blob = store.put_blob(b"x").unwrap();
    let canonical = Snapshot::new(&[entry("safe.txt", &blob, false)])
        .unwrap()
        .encode();
    let mut bad_header = canonical.clone();
    bad_header[0] ^= 0x1;
    assert_eq!(
        Snapshot::decode(&bad_header).unwrap_err().kind,
        ObjectErrorKind::InvalidSnapshot
    );

    let mut trailing = canonical.clone();
    trailing.push(0);
    assert_eq!(
        Snapshot::decode(&trailing).unwrap_err().kind,
        ObjectErrorKind::InvalidSnapshot
    );

    let mut invalid_mode = canonical.clone();
    let mode_offset = 8 + 4 + 2 + "safe.txt".len();
    invalid_mode[mode_offset] = 7;
    assert_eq!(
        Snapshot::decode(&invalid_mode).unwrap_err().kind,
        ObjectErrorKind::InvalidSnapshot
    );
    let mut count = canonical;
    count[11] = 2;
    assert_eq!(
        Snapshot::decode(&count).unwrap_err().kind,
        ObjectErrorKind::InvalidSnapshot
    );
}

#[test]
fn materialize_round_trips_content_and_never_overwrites() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let one = store.put_blob(b"fn one() {}\n").unwrap();
    let two = store.put_blob(b"#!/bin/sh\necho fine\n").unwrap();
    let id = store.put_snapshot(&[
        entry("src/main.rs", &one, false),
        entry("scripts/test.sh", &two, true)
    ]).unwrap();
    let target = fixture.path().join("checkout");
    store.materialize(&id, &target).unwrap();
    assert_eq!(fs::read(target.join("src/main.rs")).unwrap(), b"fn one() {}\n");
    assert_eq!(
        fs::read(target.join("scripts/test.sh")).unwrap(),
        b"#!/bin/sh\necho fine\n"
    );
    let before = fs::read(target.join("src/main.rs")).unwrap();
    assert_eq!(
        store.materialize(&id, &target).unwrap_err().kind,
        ObjectErrorKind::AlreadyExists
    );
    assert_eq!(fs::read(target.join("src/main.rs")).unwrap(), before);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let regular = fs::metadata(target.join("src/main.rs")).unwrap().permissions().mode();
        let executable = fs::metadata(target.join("scripts/test.sh")).unwrap().permissions().mode();
        assert_eq!(regular & 0o111, 0);
        assert_ne!(executable & 0o100, 0);
    }
}

#[test]
fn materialize_rejects_symlink_destination() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let fixture = Fixture::new();
        let store = fixture.store();
        let snapshot = store.put_snapshot(&[]).unwrap();
        let outside = fixture.path().join("outside");
        fs::create_dir(&outside).unwrap();
        symlink(&outside, fixture.path().join("alias")).unwrap();
        assert_eq!(
            store.materialize(&snapshot, &fixture.path().join("alias/new"))
                .unwrap_err().kind,
            ObjectErrorKind::UnsafePath
        );
        assert!(!outside.join("new").exists());
    }
}

#[cfg(unix)]
#[test]
fn symlinked_blob_or_shard_cannot_satisfy_verified_read() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new();
    let store = fixture.store();
    let blob = store.put_blob(b"important").unwrap();
    let blob_path = fixture.object_path(&blob);
    fs::remove_file(&blob_path).unwrap();
    let impostor = fixture.path().join("impostor");
    fs::write(&impostor, b"important").unwrap();
    symlink(&impostor, &blob_path).unwrap();
    assert_eq!(
        store.get_blob(&blob).unwrap_err().kind,
        ObjectErrorKind::UnsafePath
    );
}

#[test]
fn parallel_same_blob_writers_preserve_one_valid_object() {
    let fixture = Fixture::new();
    let store = Arc::new(fixture.store());
    let mut workers = Vec::new();
    for _ in 0..12 {
        let shared = store.clone();
        workers.push(std::thread::spawn(move || shared.put_blob(b"same").unwrap()));
    }
    let ids: Vec<_> = workers.into_iter().map(|worker| worker.join().unwrap()).collect();
    assert!(ids.iter().all(|id| id == &ids[0]));
    assert_eq!(store.get_blob(&ids[0]).unwrap(), b"same");
}

#[test]
fn no_format_marker_means_no_object_writes() {
    let fixture = Fixture::new();
    assert_eq!(
        ObjectStore::open(fixture.path()).unwrap_err().kind,
        ObjectErrorKind::InvalidStore
    );
    assert!(!fixture.path().join(".openscion/objects").exists());
}

#[test]
fn abandoned_staging_file_is_not_a_published_object() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let data = b"notyet";
    let id = ObjectId::for_content(ObjectKind::Blob, data);
    let expected_final = fixture.object_path(&id);
    let shard = expected_final.parent().unwrap();
    fs::create_dir_all(shard).unwrap();
    fs::write(shard.join(".openscion-object-abandoned"), b"unverified partial").unwrap();
    assert_eq!(
        store.get_blob(&id).unwrap_err().kind,
        ObjectErrorKind::Missing
    );
    assert_eq!(store.put_blob(data).unwrap(), id);
    assert_eq!(store.get_blob(&id).unwrap(), data);
    assert_eq!(
        fs::read(shard.join(".openscion-object-abandoned")).unwrap(),
        b"unverified partial"
    );
}

#[cfg(unix)]
#[test]
fn symlinked_object_shard_is_refused_even_with_valid_target_bytes() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new();
    let store = fixture.store();
    let id = store.put_blob(b"valid").unwrap();
    let original = fixture.object_path(&id);
    let shard = original.parent().unwrap();
    let moved = fixture.path().join("moved-shard");
    fs::rename(shard, &moved).unwrap();
    symlink(&moved, shard).unwrap();
    assert_eq!(
        store.get_blob(&id).unwrap_err().kind,
        ObjectErrorKind::UnsafePath
    );
}


#[test]
fn decoded_snapshot_with_unsafe_path_returns_invalid_snapshot_type() {
    let blob = ObjectId::for_content(ObjectKind::Blob, b"safe");
    let mut raw = Vec::new();
    raw.extend_from_slice(b"OSNAP001");
    raw.extend_from_slice(&1u32.to_be_bytes());
    raw.extend_from_slice(&6u16.to_be_bytes());
    raw.extend_from_slice(b"../bad");
    raw.push(0);
    let text = blob.to_string();
    let mut digest = [0u8; 32];
    for i in 0..32 {
        digest[i] = u8::from_str_radix(&text[(3 + 2*i)..(5 + 2*i)],16).unwrap();
    }
    raw.extend_from_slice(&digest);
    assert_eq!(
        Snapshot::decode(&raw).unwrap_err().kind,
        ObjectErrorKind::InvalidSnapshot
    );
}


#[cfg(unix)]
#[test]
fn blob_reads_fail_closed_if_object_is_group_world_accessible() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    let store = fixture.store();
    let blob = store.put_blob(b"sealed");
    let blob = blob.unwrap();
    let path = fixture.object_path(&blob);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
    assert_eq!(
        store.get_blob(&blob).unwrap_err().kind,
        ObjectErrorKind::UnsafePath
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(store.get_blob(&blob).unwrap(), b"sealed");
}

#[cfg(unix)]
#[test]
fn object_store_rejects_group_world_writable_shards() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    let store = fixture.store();
    let blob = store.put_blob(b"private").unwrap();
    let shard = fixture.object_path(&blob).parent().unwrap().to_path_buf();
    fs::set_permissions(&shard, fs::Permissions::from_mode(0o777)).unwrap();
    assert_eq!(
        store.get_blob(&blob).unwrap_err().kind,
        ObjectErrorKind::UnsafePath
    );
    fs::set_permissions(&shard, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(store.get_blob(&blob).unwrap(), b"private");
}
