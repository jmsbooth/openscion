use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Repo(PathBuf);
impl Repo {
    fn new() -> Self {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!(
            "openscion-change-cli-{}-{nanos}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        assert!(call(&["init", path.to_str().unwrap()]).status.success());
        Self(path)
    }
    fn path(&self) -> &Path { &self.0 }
    fn arg(&self) -> &str { self.0.to_str().unwrap() }
    fn empty_snapshot(&self) -> String {
        fs::write(self.path().join("empty.tsv"), b"").unwrap();
        let output = call(&["--json", "snapshot", "put", self.arg(), "empty.tsv"]);
        assert!(output.status.success(), "{}", stdout(&output));
        extract_id(&output)
    }
    fn intent(&self, text: &str) {
        fs::write(self.path().join("intent.txt"), text.as_bytes()).unwrap();
    }
}
impl Drop for Repo {
    fn drop(&mut self) { fs::remove_dir_all(&self.0).ok(); }
}

fn call(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_openscion")).args(args).output().unwrap()
}
fn stdout(out: &Output) -> String { String::from_utf8(out.stdout.clone()).unwrap() }
fn extract_id(out: &Output) -> String {
    let line = stdout(out);
    let start = line.find(r#""id":""#).unwrap() + 6;
    let remaining = &line[start..];
    remaining[..remaining.find('"').unwrap()].to_owned()
}

#[test]
fn create_root_proposal_and_revision_without_mutating_channel_state() {
    let f = Repo::new();
    let snapshot = f.empty_snapshot();
    f.intent("Implement root revision\n");
    let before = fs::read(f.path().join(".openscion/format")).unwrap();
    let proposed = call(&[
        "proposal", "create", "--json", f.arg(), "root", &snapshot, "agent_001", "intent.txt",
    ]);
    assert!(proposed.status.success(), "{}", stdout(&proposed));
    let p = extract_id(&proposed);
    assert!(p.starts_with("p1_"));
    let shown = call(&["proposal", "show", "--json", f.arg(), &p]);
    assert!(shown.status.success());
    assert!(stdout(&shown).contains(r#""actor_verified":false"#));
    assert!(stdout(&shown).contains(r#""base":null"#));
    let revised = call(&["revision", "create", "--json", f.arg(), &p]);
    assert!(revised.status.success(), "{}", stdout(&revised));
    let id = extract_id(&revised);
    assert!(id.starts_with("r1_"));
    let revision = call(&["revision", "show", "--json", f.arg(), &id]);
    assert!(revision.status.success());
    assert!(stdout(&revision).contains(&p));
    assert!(stdout(&revision).contains(r#""promoted":false"#));
    let ancestry = call(&["revision", "ancestry", "--json", f.arg(), &id]);
    assert_eq!(stdout(&ancestry).trim(),
        format!(r#"{{"ok":true,"command":"revision ancestry","revisions":["{id}"]}}"#));
    assert_eq!(fs::read(f.path().join(".openscion/format")).unwrap(), before);
    assert!(!f.path().join(".openscion/main").exists());
}

#[test]
fn two_agents_create_distinct_unpromoted_revisions_from_same_base() {
    let f = Repo::new();
    let snapshot = f.empty_snapshot();
    f.intent("Root");
    let p0 = extract_id(&call(&["proposal","create","--json",f.arg(),"root",&snapshot,"seed","intent.txt"]));
    let root = extract_id(&call(&["revision","create","--json",f.arg(),&p0]));
    f.intent("Independent change A");
    let pa = extract_id(&call(&["proposal","create","--json",f.arg(),&root,&snapshot,"agent_a","intent.txt"]));
    f.intent("Independent change B");
    let pb = extract_id(&call(&["proposal","create","--json",f.arg(),&root,&snapshot,"agent_b","intent.txt"]));
    assert_ne!(pa,pb);
    let ra = extract_id(&call(&["revision","create","--json",f.arg(),&pa]));
    let rb = extract_id(&call(&["revision","create","--json",f.arg(),&pb]));
    assert_ne!(ra,rb);
    for id in [&ra,&rb] {
        let out = call(&["revision","ancestry","--json",f.arg(),id]);
        assert_eq!(stdout(&out).trim(),
            format!(r#"{{"ok":true,"command":"revision ancestry","revisions":["{id}","{root}"]}}"#));
    }
}

#[test]
fn untrusted_intent_is_escaped_in_json_and_actor_claim_is_labeled() {
    let f = Repo::new();
    let snapshot = f.empty_snapshot();
    f.intent("Call \"reviewer\"\\tool\nand verify");
    let p = extract_id(&call(&["proposal","create","--json",f.arg(),"root",&snapshot,"agent_1","intent.txt"]));
    let out = call(&["proposal","show","--json",f.arg(),&p]);
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(text.contains(r#"Call \"reviewer\"\\tool\nand verify"#));
    assert!(text.contains(r#""actor_verified":false"#));
}

#[test]
fn invalid_intent_and_parent_type_fail_without_creating_proposals() {
    let f = Repo::new();
    let snapshot = f.empty_snapshot();
    f.intent("no\0embeddedNUL");
    let bad = call(&["proposal","create","--json",f.arg(),"root",&snapshot,"agent","intent.txt"]);
    assert_eq!(bad.status.code(),Some(8));
    assert!(stdout(&bad).contains("E_PROPOSAL_INVALID"));

    f.intent("safe");
    let bad_parent = call(&["proposal","create","--json",f.arg(),&snapshot,&snapshot,"agent","intent.txt"]);
    assert_eq!(bad_parent.status.code(),Some(8));
    assert!(stdout(&bad_parent).contains("E_OBJECT_TYPE"));

    let bogus = call(&["revision","show","--json",f.arg(),&snapshot]);
    assert_eq!(bogus.status.code(),Some(8));
    assert!(stdout(&bogus).contains("E_OBJECT_TYPE"));
}
