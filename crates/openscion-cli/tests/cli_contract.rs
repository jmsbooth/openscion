use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NONCE: AtomicU64 = AtomicU64::new(0);

struct RepoFixture(PathBuf);

impl RepoFixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "openscion-cli-{}-{}-{}",
            std::process::id(),
            nonce,
            NONCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for RepoFixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).ok();
    }
}

fn invoke(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_openscion"))
        .args(args)
        .output()
        .expect("run CLI")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

#[test]
fn help_version_and_doctor_only_advertise_implemented_commands() {
    let help = invoke(&["--help"]);
    assert!(help.status.success());
    assert!(stdout(&help).contains("init"));
    assert!(stdout(&help).contains("status"));

    let version = invoke(&["--version"]);
    assert!(version.status.success());
    assert!(stdout(&version).starts_with("openscion "));

    let doctor = invoke(&["doctor", "--json"]);
    assert!(doctor.status.success());
    assert!(stdout(&doctor).contains(r#""implemented":["init","status","blob put","blob verify""#));
    assert!(stdout(&doctor).contains(r#""pending":["promote","rollback"]"#));
}

#[test]
fn malformed_usage_returns_typed_exit_code_and_does_not_panic() {
    let no_args = invoke(&[]);
    assert_eq!(no_args.status.code(), Some(2));
    assert!(stderr(&no_args).contains("E_USAGE"));
    for arguments in [
        vec!["--json", "push"],
        vec!["--json", "init", "a", "b"],
        vec!["--json", "--json", "status"],
        vec!["--json", "--something"],
    ] {
        let failed = invoke(&arguments);
        assert_eq!(failed.status.code(), Some(2));
        assert_eq!(stdout(&failed).trim(), r#"{"ok":false,"code":"E_USAGE"}"#);
        assert!(stderr(&failed).is_empty());
    }
}

#[test]
fn json_init_and_status_are_one_line_and_do_not_expose_paths() {
    let root = RepoFixture::new();
    let name = root.path().to_str().unwrap();
    let init = invoke(&["init", "--json", name]);
    assert!(init.status.success(), "init: {}", stderr(&init));
    assert_eq!(
        stdout(&init).trim(),
        r#"{"ok":true,"command":"init","format":"openscion.local-store/1","state":"unborn"}"#
    );
    let status = invoke(&["--json", "status", name]);
    assert!(status.status.success());
    assert_eq!(
        stdout(&status).trim(),
        r#"{"ok":true,"command":"status","format":"openscion.local-store/1","state":"unborn"}"#
    );
    assert_eq!(stdout(&status).lines().count(), 1);
    assert!(!stdout(&status).contains(name));
}

#[test]
fn status_before_init_is_explicit_error_and_never_creates_state() {
    let root = RepoFixture::new();
    let out = invoke(&["status", "--json", root.path().to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(4));
    assert_eq!(
        stdout(&out).trim(),
        r#"{"ok":false,"code":"E_NOT_INITIALIZED"}"#
    );
    assert!(!root.path().join(".openscion").exists());
}

#[test]
fn invalid_marker_and_reinit_are_distinct_errors() {
    let root = RepoFixture::new();
    let name = root.path().to_str().unwrap();
    assert!(invoke(&["init", name]).status.success());
    assert_eq!(invoke(&["init", name]).status.code(), Some(5));
    fs::write(root.path().join(".openscion/format"), b"bad\n").unwrap();
    let invalid = invoke(&["status", "--json", name]);
    assert_eq!(invalid.status.code(), Some(6));
    assert_eq!(
        stdout(&invalid).trim(),
        r#"{"ok":false,"code":"E_INVALID_STORE"}"#
    );
}

#[test]
fn source_control_operations_are_deliberately_unimplemented() {
    let root = RepoFixture::new();
    let name = root.path().to_str().unwrap();
    let result = invoke(&["--json", "promote", name]);
    assert_eq!(result.status.code(), Some(2));
    assert_eq!(stdout(&result).trim(), r#"{"ok":false,"code":"E_USAGE"}"#);
    assert!(!root.path().join(".openscion").exists());
}

#[cfg(unix)]
#[test]
fn non_utf8_input_is_rejected_without_echoing_untrusted_bytes() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    let out = Command::new(env!("CARGO_BIN_EXE_openscion"))
        .arg("--json")
        .arg(OsString::from_vec(vec![0xff]))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(stdout(&out).trim(), r#"{"ok":false,"code":"E_USAGE"}"#);
    assert!(stderr(&out).is_empty());
}
