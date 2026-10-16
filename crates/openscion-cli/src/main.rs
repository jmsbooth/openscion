//! OpenScion M1 increment 1 CLI. No source-control changes are supported yet.

use openscion_core::{initialize_repository, inspect_repository, StoreError};
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
                "JSON errors are stable and do not include filesystem paths.\n",
            ),
            r#"{"ok":true,"command":"help","implemented":["help","version","doctor","init","status"]}"#,
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
                "Implemented: init, status\n",
                "Pending: propose, verify, promote, rollback\n",
                "Storage: local format marker only (no revision storage)\n",
            ),
            r#"{"ok":true,"command":"doctor","implemented":["init","status"],"pending":["propose","verify","promote","rollback"],"storage":"local-bootstrap"}"#,
        )),
        ["init"] => bootstrap("init", "."),
        ["init", path] => bootstrap("init", path),
        ["status"] => bootstrap("status", "."),
        ["status", path] => bootstrap("status", path),
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
