//! OpenScion M1 increment 1 CLI. No source-control changes are supported yet.

use openscion_core::{initialize_repository, inspect_repository, StoreError};
use openscion_core::objects::{ObjectError, ObjectId, ObjectStore, SnapshotEntry, MAX_SNAPSHOT_BYTES};
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
                "OpenScion local bootstrap (no revisions or promotions)\n",
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
                "JSON errors are stable and do not include filesystem paths.\n",
            ),
            r#"{"ok":true,"command":"help","implemented":["help","version","doctor","init","status","blob put","blob verify","snapshot put","snapshot show","snapshot materialize"]}"#,
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
                "OpenScion local-only bootstrap\n",
                "Implemented: init, status, blob put/verify, snapshot put/show/materialize\n",
                "Pending: propose, verify, promote, rollback\n",
                "Storage: local format marker only (no revision storage)\n",
            ),
            r#"{"ok":true,"command":"doctor","implemented":["init","status","blob put","blob verify","snapshot put","snapshot show","snapshot materialize"],"pending":["propose","promote","rollback"],"storage":"local-cas-v1"}"#,
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
        "Initialized OpenScion local store (unborn; no revisions)"
    } else {
        "OpenScion local store: unborn (no revisions)"
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
