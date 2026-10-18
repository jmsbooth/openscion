# FOSS-387 — Manual functional and security qualification

**Scope:** Rust workspace, local CLI bootstrap, fail-closed format validation. **Not included:** changes, manifests, revision history, provenance, approval, promotion or rollback.

Follow commands individually on your own machine. Observe actual output and verify exit status. Never treat a script or a "passed" summary as qualification. GitHub Actions are not part of this gate.

## Environment and evidence

Record UTC execution time, OS/build, compiler/runtime versions, source SHA, reviewer, exact commands, stdout/stderr, exit codes, test fixture path and SHA-256 of artifacts. Keep raw logs outside the repository if they contain local paths or credentials. Redact sensitive content before sharing.

### Windows PowerShell

From the repository root (FOSS-387 source branch):

    git rev-parse HEAD
    rustc --version
    cargo --version
    rustup show active-toolchain
    cargo metadata --offline --format-version 1
    cargo test -p openscion-core --offline --test repository_contract -- --nocapture
    cargo test -p openscion-cli --offline --test cli_contract -- --nocapture
    cargo test --workspace --offline -- --nocapture
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets --offline -- -D warnings
    cargo build --workspace --offline

A tool that is absent, or fails to run, is BLOCKED or FAIL and must be recorded; never silently skip. The rust-toolchain file pins 1.85.1. Installing a missing toolchain is a separate approved workstation operation, not an implicit CI action.

**Manually exercise CLI behavior:**

    $bin = Join-Path (Get-Location) "target\debug\openscion.exe"
    & $bin --help
    $LASTEXITCODE
    & $bin --version
    $LASTEXITCODE
    & $bin doctor --json
    $LASTEXITCODE

Use a new test directory not containing production files:

    $root = Join-Path $env:TEMP ("openscion-manual-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $root
    & $bin --json status $root
    $LASTEXITCODE
    & $bin --json init $root
    $LASTEXITCODE
    Get-ChildItem -Force (Join-Path $root ".openscion")
    $marker = Join-Path $root ".openscion\format"
    [System.Text.Encoding]::UTF8.GetString([System.IO.File]::ReadAllBytes($marker))
    (Get-FileHash -Algorithm SHA256 $marker).Hash
    & $bin --json status $root
    $LASTEXITCODE
    & $bin --json init $root
    $LASTEXITCODE
    & $bin --json promote $root
    $LASTEXITCODE

Expected: status before init -> E_NOT_INITIALIZED (4); initialization -> success (0) and "unborn"; exact marker text "openscion.local-store/1" plus LF; status -> success; reinit -> E_ALREADY_INITIALIZED (5); unsupported promote -> E_USAGE (2), no modification to marker bytes.

**Corruption and path security:**

    [System.IO.File]::WriteAllBytes($marker, [System.Text.Encoding]::ASCII.GetBytes("tampered" + [char]10))
    & $bin --json status $root
    $LASTEXITCODE
    & $bin --json init $root
    $LASTEXITCODE
    & $bin --json init (Join-Path $root "..\elsewhere")
    $LASTEXITCODE
    & $bin --json init (Join-Path $root "missing")
    $LASTEXITCODE

Expected: tampered status -> E_INVALID_STORE (6); reinit -> E_ALREADY_INITIALIZED (5), must not repair; traversing path -> E_UNSAFE_PATH (3); missing directory -> E_NOT_DIRECTORY (3). Record observed deviations. Clean temporary files only after evidence is collected.

Windows junction/reparse-point rejection is **not certified** by the Unix symlink tests. Exercise it with disposable directories on Windows and capture results. Do not claim Windows path containment is adversarially secure based solely on bootstrap checks.

### Linux/macOS shell

    git rev-parse HEAD
    rustc --version
    cargo --version
    cargo test --workspace --offline -- --nocapture
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets --offline -- -D warnings
    cargo build --workspace --offline
    fixture="$(mktemp -d)"
    ./target/debug/openscion --json status "$fixture"
    echo "exit=$?"
    ./target/debug/openscion --json init "$fixture"
    echo "exit=$?"
    od -An -tx1 "$fixture/.openscion/format"
    sha256sum "$fixture/.openscion/format"
    ./target/debug/openscion --json status "$fixture"
    echo "exit=$?"
    ./target/debug/openscion --json init "$fixture"
    echo "exit=$?"
    ./target/debug/openscion --json promote "$fixture"
    echo "exit=$?"
    printf 'bad\n' > "$fixture/.openscion/format"
    ./target/debug/openscion --json status "$fixture"
    echo "exit=$?"

All outputs and exit statuses must be retained, not just expected values. This is a list of individually inspectable commands, not a certification script.

## Requirement-to-evidence matrix

| Case | Contract | Expected outcome |
|---|---|---|
| F387-01 | help, version, doctor | Exit 0; implementation scope represented accurately |
| F387-02 | status before init | Exit 4, E_NOT_INITIALIZED, no metadata created |
| F387-03 | init and inspect | Exit 0, exact marker bytes, unborn |
| F387-04 | double init | Exit 5, E_ALREADY_INITIALIZED, marker unchanged |
| F387-05 | tampered/oversized/partial metadata | Exit 6, E_INVALID_STORE, no silent repair |
| F387-06 | traversal/symlink components | Exit 3, E_UNSAFE_PATH, no outside writes |
| F387-07 | unsupported commands/invalid flags | Exit 2, E_USAGE, no side effects |
| F387-08 | JSON mode | one JSON line on stdout, stable error codes, no untrusted path strings |
| F387-09 | offline build/test | rustc/cargo version captured and suites executed |
| F387-10 | compiler lint/format | fmt/clippy output reviewed |
| F387-11 | crash during initialization | invalid/partial status only, never false success (fault injection pending) |
| F387-12 | Windows junction/ACL behavior | manually observed and recorded on Windows (pending) |

## Qualification decision

Do not close FOSS-387 until compiler, tests, interactive commands, security regression cases, and evidence review are complete. Static source inspection is not equivalent to Rust compilation or executable test coverage.


## Additional Unix metadata-permissions security check

After successful init on a disposable fixture, execute each step independently and inspect its exit status:

    chmod 777 "$fixture/.openscion"
    ./target/debug/openscion --json status "$fixture"
    echo "exit=$?"
    chmod 700 "$fixture/.openscion"
    chmod 666 "$fixture/.openscion/format"
    ./target/debug/openscion --json status "$fixture"
    echo "exit=$?"
    chmod 600 "$fixture/.openscion/format"
    ./target/debug/openscion --json status "$fixture"
    echo "exit=$?"

Expected: each permissive mode fails with E_INVALID_STORE (6); after private permissions are restored, status reports unborn. This is a permissions regression test, not evidence of resistance to hostile same-UID races. Windows native inherited ACLs remain a separate mandatory review.
