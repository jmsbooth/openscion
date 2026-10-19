use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "openscion-cli-cas-{}-{}-{}",
            std::process::id(),
            time,
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        let init = run(&["init", path.to_str().unwrap()]);
        assert!(init.status.success());
        Self(path)
    }
    fn root(&self) -> &Path {
        &self.0
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).ok();
    }
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_openscion"))
        .args(args)
        .output()
        .unwrap()
}

fn stdout(out: &Output) -> String {
    String::from_utf8(out.stdout.clone()).unwrap()
}

fn id_from_json(out: &Output) -> String {
    let output = stdout(out);
    let start = output.find(r#""id":""#).unwrap() + 6;
    let remaining = &output[start..];
    remaining[..remaining.find('"').unwrap()].to_string()
}

#[test]
fn manually_inspectable_blob_snapshot_and_materialize_round_trip() {
    let fixture = Fixture::new();
    let root = fixture.root().to_str().unwrap();
    fs::create_dir(fixture.root().join("src")).unwrap();
    fs::write(fixture.root().join("src/main.rs"), b"pub fn main() {}\n").unwrap();

    let blob = run(&["--json", "blob", "put", root, "src/main.rs"]);
    assert!(blob.status.success(), "{}", stdout(&blob));
    let blob_id = id_from_json(&blob);
    assert!(blob_id.starts_with("b1_"));
    assert_eq!(blob_id.len(), 67);

    let verified = run(&["blob", "verify", "--json", root, &blob_id]);
    assert!(verified.status.success());
    assert!(stdout(&verified).contains(r#""command":"blob verify""#));

    fs::write(
        fixture.root().join("manifest.tsv"),
        format!("src/main.rs\t{blob_id}\t0\n"),
    )
    .unwrap();
    let snapshot = run(&["snapshot", "put", "--json", root, "manifest.tsv"]);
    assert!(snapshot.status.success(), "{}", stdout(&snapshot));
    let snapshot_id = id_from_json(&snapshot);
    assert!(snapshot_id.starts_with("s1_"));

    let show = run(&["snapshot", "show", "--json", root, &snapshot_id]);
    assert!(show.status.success());
    assert!(stdout(&show).contains(r#""path":"src/main.rs""#));
    assert!(stdout(&show).contains(&blob_id));

    let target = fixture.root().join("restored");
    let restored = run(&[
        "snapshot",
        "materialize",
        "--json",
        root,
        &snapshot_id,
        target.to_str().unwrap(),
    ]);
    assert!(restored.status.success(), "{}", stdout(&restored));
    assert_eq!(
        fs::read(target.join("src/main.rs")).unwrap(),
        b"pub fn main() {}\n"
    );

    let duplicate = run(&[
        "snapshot",
        "materialize",
        "--json",
        root,
        &snapshot_id,
        target.to_str().unwrap(),
    ]);
    assert_eq!(duplicate.status.code(), Some(5));
    assert_eq!(
        stdout(&duplicate).trim(),
        r#"{"ok":false,"code":"E_ALREADY_EXISTS"}"#
    );
}

#[test]
fn corrupted_blob_verification_fails_closed() {
    let fixture = Fixture::new();
    let root = fixture.root().to_str().unwrap();
    fs::write(fixture.root().join("safe.txt"), b"SAFE").unwrap();
    let saved = run(&["blob", "put", "--json", root, "safe.txt"]);
    assert!(saved.status.success());
    let id = id_from_json(&saved);
    let raw = &id[3..];
    let object = fixture
        .root()
        .join(".openscion/objects/b1")
        .join(&raw[..2])
        .join(raw);
    fs::write(object, b"EVIL").unwrap();
    let failed = run(&["blob", "verify", "--json", root, &id]);
    assert_eq!(failed.status.code(), Some(10));
    assert_eq!(
        stdout(&failed).trim(),
        r#"{"ok":false,"code":"E_OBJECT_CORRUPT"}"#
    );
}

#[test]
fn invalid_or_unsafe_manifest_is_rejected_without_publishing_snapshot() {
    let fixture = Fixture::new();
    let root = fixture.root().to_str().unwrap();
    fs::write(fixture.root().join("a.txt"), b"good").unwrap();
    let blob = run(&["blob", "put", "--json", root, "a.txt"]);
    let id = id_from_json(&blob);
    for manifest in [
        format!("../escape\t{id}\t0\n"),
        format!("CON.txt\t{id}\t0\n"),
        format!("readme.md\t{id}\t0\nREADME.md\t{id}\t0\n"),
    ] {
        fs::write(fixture.root().join("manifest.tsv"), manifest).unwrap();
        let denied = run(&["snapshot", "put", "--json", root, "manifest.tsv"]);
        assert!(!denied.status.success());
        assert!(stdout(&denied).contains(r#""ok":false"#));
        assert!(!stdout(&denied).contains("escape"));
    }

    fs::write(
        fixture.root().join("manifest.tsv"),
        format!("safe.txt\t{id}\t0"),
    )
    .unwrap();
    let no_final_lf = run(&["snapshot", "put", "--json", root, "manifest.tsv"]);
    assert_eq!(no_final_lf.status.code(), Some(2));
}

#[cfg(unix)]
#[test]
fn blob_import_rejects_symlink_source() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new();
    let root = fixture.root().to_str().unwrap();
    let target = fixture.root().join("outside");
    fs::write(&target, b"private").unwrap();
    symlink(&target, fixture.root().join("shortcut")).unwrap();
    let denied = run(&["blob", "put", "--json", root, "shortcut"]);
    assert_eq!(denied.status.code(), Some(3));
    assert_eq!(
        stdout(&denied).trim(),
        r#"{"ok":false,"code":"E_UNSAFE_PATH"}"#
    );
}
