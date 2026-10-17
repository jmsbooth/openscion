# SPEC-001A — Local Rust workspace and CLI bootstrap

**Issue:** FOSS-387 | **Stage:** M1 increment 1 | **Status:** implementation contract

## Intent and boundaries

This increment creates a dependency-free Rust workspace and a narrowly functional local repository bootstrap. It is **not a working source-control replacement**: no blobs, revisions, proposals, approvals, promotion, provenance or rollback are accepted yet.

The binary is named "openscion", with two packages: "openscion-core" (library) and "openscion-cli" (binary). Source code, tests and package dependencies use the Rust standard library only. No network requests are performed by any CLI command.

## Requirements

| ID | Behavior and explicit outcome |
|---|---|
| R-001 | "openscion --help" / "help" shows implemented commands; "version" and "--version" show the Cargo package version; "doctor" lists implemented and pending operations. |
| R-002 | "init [path]" initializes an *existing* directory and creates ".openscion/format" containing exactly "openscion.local-store/1" plus one final LF. Omitted path means current directory. |
| R-003 | "status [path]" verifies the store marker and reports "unborn". The marker is a format sentinel only; it makes **no claim** of code provenance or revision security. |
| R-004 | "--json" (at most once, in any argument position) requests one JSON line on stdout for success or error. Machine-readable failures contain only stable codes (no untrusted paths, secrets or OS errors). |
| R-005 | Return documented nonzero statuses for unsupported commands, invalid input, symlinks in the supplied path or metadata, existing repositories, malformed storage and IO failures. Unknown command never creates or modifies a repository. |
| R-006 | Initialization refuses to overwrite an existing ".openscion" directory or file, and uses exclusive creation for both the directory and marker. Reinitialization leaves existing bytes intact. |
| R-007 | Reject an input path containing parent traversal, including symlinks in any ancestor. Reject metadata symlinks and marker symlinks. Require the target directory to preexist. |
| R-008 | Write marker through a freshly created staging file, flush it with sync_all, publish via an atomic no-overwrite hard link within the repository metadata directory, then remove the staging name, and sync that directory where supported. On interrupted setup, fail closed (not status OK). |
| R-009 | Unknown flags, duplicate "--json", non-UTF8 CLI arguments, extra positional arguments, unsupported actions and malformed objects cannot cause a panic. |
| R-010 | Do not require GitHub Actions, remote services, dependencies, user credentials or any network operation for normal runtime and tests. |

## CLI contract

    openscion --help
    openscion --version
    openscion doctor [--json]
    openscion init [--json] [path]
    openscion status [--json] [path]

Successful init --json: {"ok":true,"command":"init","format":"openscion.local-store/1","state":"unborn"}.
Successful status --json: {"ok":true,"command":"status","format":"openscion.local-store/1","state":"unborn"}.
Error JSON: {"ok":false,"code":"E_<TYPE>"} (a single line).
Codes/exits: E_USAGE (2), E_UNSAFE_PATH (3), E_NOT_DIRECTORY (3), E_NOT_INITIALIZED (4), E_ALREADY_INITIALIZED (5), E_INVALID_STORE (6), E_IO (7).

## Failure and security policy

- A compromised local user with concurrent write permissions can race filesystem operations. M1 bootstrap reduces accidental hazards; it does **not** guarantee resistance to a hostile same-user adversary racing directory replacement. The later service must use trusted directory handles, sandboxing and stronger protections.
- OS-specific symlink/junction behavior requires platform coverage, including Windows reparse points.
- No fallback to overwrite a damaged store; manual recovery is intentionally out of scope. "status" refuses partial or corrupted metadata.
- Strict marker verification is a version negotiation *precursor*, not a source-content integrity proof.
- No content-addressed persistence, provenance or access-control claims are made under this issue.

## Test-first requirements

Tests in "crates/openscion-core/tests/repository_contract.rs" and "crates/openscion-cli/tests/cli_contract.rs" are authored before implementation. Tests cover exact marker, unborn state, reinit safety, missing root, malformed metadata, partial initialization, traversal, symlink components, unknown command, JSON errors, help/version/doctor and unsupported source-control commands.

**Manual qualification:**
1. Inspect test source and output of cargo test --workspace --offline -- --nocapture (raw test names/counts).
2. Run cargo fmt --all -- --check and cargo clippy --workspace --all-targets --offline -- -D warnings individually.
3. Follow docs/engineering/foss-387-manual-qa.md; inspect ".openscion/format" bytes and actual status/exit codes.
4. Archive raw logs, source SHA and artifacts with hashes. If Cargo is absent, label runtime tests **BLOCKED**, not passed.
