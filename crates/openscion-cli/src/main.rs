//! OpenScion M1 increment 1 CLI. No source-control changes are supported yet.

use openscion_core::{initialize_repository, inspect_repository, StoreError};
use openscion_core::objects::{ChangeError, ObjectError, ObjectId, ObjectStore, Proposal, SnapshotEntry, MAX_PROPOSAL_BYTES, MAX_SNAPSHOT_BYTES};
use std::env;
use std::path::Path;
use std::process::ExitCode;

struct Reply {
    human: String,
    json: String,
}

impl Reply {
    fn new(human: impl Into<String>, json: impl Into<String>) -> Self {
        Self {
            human: human.into(),
            json: json.into(),
        }
    }
}

struct CliFailure {
    code: &'static str,
    status: u8,
    message: String,
}

impl CliFailure {
    fn usage(message: impl Into<String>) -> Self {
        Self {
            code: "E_USAGE",
            status: 2,
            message: message.into(),
        }
    }
}

impl From<ChangeError> for CliFailure {
    fn from(failure: ChangeError) -> Self {
        Self {
            code: failure.kind.code(),
            status: failure.kind.exit_code(),
            message: failure.message,
        }
    }
}

impl From<ObjectError> for CliFailure {
    fn from(failure: ObjectError) -> Self {
        Self {
            code: failure.kind.code(),
            status: failure.kind.exit_code(),
            message: failure.message,
        }
    }
}

impl From<StoreError> for CliFailure {
    fn from(failure: StoreError) -> Self {
        Self {
            code: failure.code.as_str(),
            status: failure.code.exit_code(),
            message: failure.message,
        }
    }
}

fn main() -> ExitCode {
    let raw: Vec<_> = env::args_os().skip(1).collect();
    let json = raw
        .iter()
        .any(|argument| argument.to_str() == Some("--json"));
    let arguments = match raw
        .into_iter()
        .map(|argument| argument.into_string())
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(arguments) => arguments,
        Err(_) => {
            return emit_failure(
                &CliFailure::usage("command arguments must be UTF-8"),
                json,
            )
        }
    };

    match run(&arguments) {
        Ok(reply) => {
            if json {
                println!("{}", reply.json);
            } else {
                println!("{}", reply.human);
            }
            ExitCode::SUCCESS
        }
        Err(error) => emit_failure(&error, json),
    }
}

fn emit_failure(error: &CliFailure, json: bool) -> ExitCode {
    if json {
        // The code is an internal constant. Caller-supplied strings and OS
        // errors never enter the machine-readable response.
        println!(r#"{{"ok":false,"code":"{}"}}"#, error.code);
    } else {
        eprintln!("{}: {}", error.code, error.message);
    }
    ExitCode::from(error.status)
}

fn run(raw: &[String]) -> Result<Reply, CliFailure> {
    if raw.iter().filter(|value| value.as_str() == "--json").count() > 1 {
        return Err(CliFailure::usage("--json may be specified only once"));
    }

    let arguments: Vec<&str> = raw
        .iter()
        .map(String::as_str)
        .filter(|value| *value != "--json")
        .collect();

    if arguments.len() > 1 && arguments[1].starts_with('-') {
        return Err(CliFailure::usage("unknown option"));
    }

    match arguments.as_slice() {
        ["--help"] | ["-h"] | ["help"] => Ok(Reply::new(
            concat!(
                "OpenScion local candidate store (promotion and rollback pending)\n",
                "Usage:\n",
                "  openscion --help\n",
                "  openscion --version\n",
                "  openscion doctor [--json]\n",
                "  openscion init [--json] [existing-directory]\n",
                "  openscion status [--json] [existing-directory]\n",
                "  openscion blob put [--json] <repo> <repo-relative-file>\n",
                "  openscion blob verify [--json] <repo> <b1_ID>\n",
                "  openscion snapshot put [--json] <repo> <repo-relative-manifest.tsv>\n",
                "  openscion snapshot show [--json] <repo> <s1_ID>\n",
                "  openscion snapshot materialize [--json] <repo> <s1_ID> <new-directory>\n",
                "  openscion proposal create <repo> <root|r1_ID> <s1_ID> <actor> <intent-file>\n",
                "  openscion proposal show <repo> <p1_ID>\n",
                "  openscion revision create <repo> <p1_ID>\n",
                "  openscion revision show <repo> <r1_ID>\n",
                "  openscion revision ancestry <repo> <r1_ID>\n",
                "JSON errors are stable and do not include filesystem paths.\n",
            ),
            r#"{"ok":true,"command":"help","implemented":["help","version","doctor","init","status","blob put","blob verify","snapshot put","snapshot show","snapshot materialize","proposal create","proposal show","revision create","revision show","revision ancestry"]}"#,
        )),
        ["--version"] | ["version"] => Ok(Reply::new(
            format!("openscion {}", env!("CARGO_PKG_VERSION")),
            format!(
                r#"{{"ok":true,"command":"version","version":"{}"}}"#,
                env!("CARGO_PKG_VERSION")
            ),
        )),
        ["doctor"] => Ok(Reply::new(
            concat!(
                "OpenScion local immutable candidate store\n",
                "Implemented: init, status, blob put/verify, snapshot put/show/materialize, proposal create/show, revision create/show/ancestry\n",
                "Pending: promote, rollback\n",
                "Storage: immutable blobs, snapshots and unpromoted revisions\n",
            ),
            r#"{"ok":true,"command":"doctor","implemented":["init","status","blob put","blob verify","snapshot put","snapshot show","snapshot materialize","proposal create","proposal show","revision create","revision show","revision ancestry"],"pending":["promote","rollback"],"storage":"local-cas-v1"}"#,
        )),
        ["init"] => bootstrap("init", "."),
        ["init", path] => bootstrap("init", path),
        ["status"] => bootstrap("status", "."),
        ["status", path] => bootstrap("status", path),
        ["blob", "put", repo, relative] => blob_put(repo, relative),
        ["blob", "verify", repo, id] => blob_verify(repo, id),
        ["snapshot", "put", repo, manifest] => snapshot_put(repo, manifest),
        ["snapshot", "show", repo, id] => snapshot_show(repo, id),
        ["snapshot", "materialize", repo, id, target] => snapshot_materialize(repo, id, target),
        ["proposal", "create", repo, base, snapshot, actor, intent] => proposal_create(repo, base, snapshot, actor, intent),
        ["proposal", "show", repo, id] => proposal_show(repo, id),
        ["revision", "create", repo, proposal] => revision_create(repo, proposal),
        ["revision", "show", repo, id] => revision_show(repo, id),
        ["revision", "ancestry", repo, id] => revision_ancestry(repo, id),
        _ => Err(CliFailure::usage(
            "unsupported command or invalid number of arguments; see --help",
        )),
    }
}

fn bootstrap(command: &'static str, path: &str) -> Result<Reply, CliFailure> {
    let target = Path::new(path);
    if command == "init" {
        initialize_repository(target)?;
    } else {
        inspect_repository(target)?;
    }

    let human = if command == "init" {
        "Initialized OpenScion local store (unborn; no promoted head)"
    } else {
        "OpenScion local store: unborn (no promoted head)"
    };

    Ok(Reply::new(
        human,
        format!(
            r#"{{"ok":true,"command":"{command}","format":"openscion.local-store/1","state":"unborn"}}"#
        ),
    ))
}


fn blob_put(repo: &str, relative: &str) -> Result<Reply, CliFailure> {
    let store = ObjectStore::open(Path::new(repo))?;
    let id = store.put_repo_file(relative)?;
    Ok(Reply::new(
        format!("Stored immutable blob {id}"),
        format!(r#"{{"ok":true,"command":"blob put","id":"{id}"}}"#),
    ))
}

fn blob_verify(repo: &str, raw_id: &str) -> Result<Reply, CliFailure> {
    let store = ObjectStore::open(Path::new(repo))?;
    let id = ObjectId::parse(raw_id)?;
    let contents = store.get_blob(&id)?;
    Ok(Reply::new(
        format!("Verified {id} ({} bytes)", contents.len()),
        format!(r#"{{"ok":true,"command":"blob verify","id":"{id}","bytes":{}}}"#, contents.len()),
    ))
}

fn snapshot_put(repo: &str, manifest: &str) -> Result<Reply, CliFailure> {
    let store = ObjectStore::open(Path::new(repo))?;
    let bytes = store.read_repo_file(manifest, MAX_SNAPSHOT_BYTES)?;
    let data = std::str::from_utf8(&bytes)
        .map_err(|_| CliFailure::usage("manifest must be UTF-8"))?;
    let mut entries = Vec::new();
    if !data.is_empty() && !data.ends_with('\n') {
        return Err(CliFailure::usage("manifest must end with LF"));
    }
    for line in data.split_terminator('\n') {
        if line.is_empty() {
            return Err(CliFailure::usage("empty manifest line"));
        }
        let columns: Vec<&str> = line.split('\t').collect();
        if columns.len() != 3 {
            return Err(CliFailure::usage("manifest lines require path, blob ID and 0/1 mode"));
        }
        let executable = match columns[2] {
            "0" => false,
            "1" => true,
            _ => return Err(CliFailure::usage("manifest mode must be 0 or 1")),
        };
        entries.push(SnapshotEntry {
            path: columns[0].to_owned(),
            blob: ObjectId::parse(columns[1])?,
            executable,
        });
    }
    let id = store.put_snapshot(&entries)?;
    Ok(Reply::new(
        format!("Stored canonical snapshot {id}"),
        format!(r#"{{"ok":true,"command":"snapshot put","id":"{id}","entries":{}}}"#, entries.len()),
    ))
}

fn snapshot_show(repo: &str, raw_id: &str) -> Result<Reply, CliFailure> {
    let store = ObjectStore::open(Path::new(repo))?;
    let id = ObjectId::parse(raw_id)?;
    let entries = store.get_snapshot(&id)?;
    let mut human = String::new();
    let mut json_entries = Vec::with_capacity(entries.len());
    for entry in &entries {
        let mode = u8::from(entry.executable);
        human.push_str(&format!("{}\t{}\t{mode}\n", entry.path, entry.blob));
        // Snapshot path policy excludes quotation marks, control characters,
        // backslashes and Unicode; these strings are safe in JSON literals.
        json_entries.push(format!(
            r#"{{"path":"{}","blob":"{}","mode":{mode}}}"#,
            entry.path, entry.blob
        ));
    }
    Ok(Reply::new(
        human,
        format!(
            r#"{{"ok":true,"command":"snapshot show","id":"{id}","entries":[{}]}}"#,
            json_entries.join(",")
        ),
    ))
}

fn snapshot_materialize(repo: &str, raw_id: &str, destination: &str) -> Result<Reply, CliFailure> {
    let store = ObjectStore::open(Path::new(repo))?;
    let id = ObjectId::parse(raw_id)?;
    store.materialize(&id, Path::new(destination))?;
    Ok(Reply::new(
        "Materialized verified snapshot into new directory",
        format!(r#"{{"ok":true,"command":"snapshot materialize","id":"{id}"}}"#),
    ))
}


fn proposal_create(
    repo: &str,
    raw_base: &str,
    raw_snapshot: &str,
    actor: &str,
    intent_file: &str,
) -> Result<Reply, CliFailure> {
    let store = ObjectStore::open(Path::new(repo))?;
    let base = if raw_base == "root" {
        None
    } else {
        Some(ObjectId::parse(raw_base)?)
    };
    let snapshot = ObjectId::parse(raw_snapshot)?;
    let bytes = store.read_repo_file(intent_file, MAX_PROPOSAL_BYTES)?;
    let intent = std::str::from_utf8(&bytes)
        .map_err(|_| CliFailure::usage("intent file is not valid UTF-8"))?;
    let proposed = Proposal::new(base, snapshot, actor, intent)?;
    let id = store.put_proposal(&proposed)?;
    Ok(Reply::new(
        format!("Created immutable proposal {id} (UNVERIFIED actor claim)"),
        format!(r#"{{"ok":true,"command":"proposal create","id":"{id}","actor_verified":false}}"#),
    ))
}

fn proposal_show(repo: &str, raw_id: &str) -> Result<Reply, CliFailure> {
    let store = ObjectStore::open(Path::new(repo))?;
    let id = ObjectId::parse(raw_id)?;
    let proposal = store.get_proposal(&id)?;
    let base = proposal.base().map(ToString::to_string);
    let parent_text = base.as_deref().unwrap_or("root");
    let json_parent = base.as_ref()
        .map(|parent| format!(r#""{parent}""#))
        .unwrap_or_else(|| "null".to_owned());
    Ok(Reply::new(
        format!("Proposal {id}\nbase: {parent_text}\nsnapshot: {}\nactor (UNVERIFIED): {}\nintent:\n{}\n",
                proposal.snapshot(),proposal.actor_claim(),proposal.intent()),
        format!(r#"{{"ok":true,"command":"proposal show","id":"{id}","base":{json_parent},"snapshot":"{}","actor_claim":"{}","actor_verified":false,"intent":"{}"}}"#,
                proposal.snapshot(),proposal.actor_claim(),json_escape(proposal.intent())),
    ))
}

fn revision_create(repo: &str, raw_proposal: &str) -> Result<Reply, CliFailure> {
    let store = ObjectStore::open(Path::new(repo))?;
    let proposal = ObjectId::parse(raw_proposal)?;
    let id = store.create_revision(&proposal)?;
    Ok(Reply::new(
        format!("Created unpromoted revision {id}"),
        format!(r#"{{"ok":true,"command":"revision create","id":"{id}","promoted":false}}"#),
    ))
}

fn revision_show(repo: &str, raw_id: &str) -> Result<Reply, CliFailure> {
    let store = ObjectStore::open(Path::new(repo))?;
    let id = ObjectId::parse(raw_id)?;
    let revision = store.get_revision(&id)?;
    let parent = revision.parent().map(ToString::to_string);
    let parent_text = parent.as_deref().unwrap_or("root");
    let json_parent = parent.as_ref()
        .map(|parent| format!(r#""{parent}""#))
        .unwrap_or_else(|| "null".to_owned());
    Ok(Reply::new(
        format!("Revision {id}\nparent: {parent_text}\nsnapshot: {}\nproposal: {}\npromoted: false",
                revision.snapshot(), revision.proposal()),
        format!(r#"{{"ok":true,"command":"revision show","id":"{id}","parent":{json_parent},"snapshot":"{}","proposal":"{}","promoted":false}}"#,
                revision.snapshot(),revision.proposal()),
    ))
}

fn revision_ancestry(repo: &str, raw_id: &str) -> Result<Reply, CliFailure> {
    let store = ObjectStore::open(Path::new(repo))?;
    let id = ObjectId::parse(raw_id)?;
    let chain = store.ancestry(&id)?;
    let human = chain.iter().map(ToString::to_string).collect::<Vec<_>>().join("\n");
    let json = chain.iter().map(|id| format!(r#""{id}""#)).collect::<Vec<_>>().join(",");
    Ok(Reply::new(
        human,
        format!(r#"{{"ok":true,"command":"revision ancestry","revisions":[{json}]}}"#),
    ))
}

/// Minimal, explicit JSON string escaping for untrusted UTF-8 intent strings.
/// No author-provided string is interpolated into JSON without this function
/// except actor claim, which uses a strict ASCII identifier grammar.
fn json_escape(source: &str) -> String {
    let mut out = String::new();
    for c in source.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c <= '\u{1f}' => {
                use std::fmt::Write;
                write!(&mut out, "\\u{:04x}", c as u32).expect("String write cannot fail");
            }
            _ => out.push(c),
        }
    }
    out
}
