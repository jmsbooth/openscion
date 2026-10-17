# FOSS-388 — Local manual qualification of immutable objects and snapshots

## Preconditions / evidence

- Must run against exact PR #3 head commit on a host with Rust 1.85.1, Cargo, rustfmt and Clippy. Parent PR #2 is an unqualified dependency: qualify PR #2 first.
- SHA-2 dependency is pinned at 0.10.9, but Cargo.lock was not generated in this executor. On an approved network-connected workstation, resolve dependencies, generate Cargo.lock, capture checksum/license/SBOM/security review and commit the lockfile. After that, use cargo --locked --offline for reproducible runs with a populated local registry cache.
- Run **individual commands** and inspect named outputs, expected/actual results, filesystem changes and nonzero exit codes. Record exact source SHA, OS, compiler, Cargo version, SHA-256 of objects, test logs and independent reviewer.
- Do not invoke GitHub Actions (no credits). Missing OS/toolchain/case is NOT_RUN or BLOCKED, never PASS.
- Local temporary fixture MUST NOT contain production source, secrets or credentials. Test in isolated repo copies.

## Rust toolchain and test gate (each command independently)

    git rev-parse HEAD
    rustc --version
    cargo --version
    rustup show active-toolchain
    cargo generate-lockfile
    cargo metadata --locked --offline --format-version 1
    cargo test -p openscion-core --test object_contract --locked --offline -- --nocapture
    cargo test -p openscion-cli --test object_cli_contract --locked --offline -- --nocapture
    cargo test --workspace --locked --offline -- --nocapture
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets --locked --offline -- -D warnings
    cargo build --workspace --locked --offline

Perform a separate dependency vulnerability/licensing scan on Cargo.lock before accepting RustCrypto + transitive crates. An offline Rust command may report dependency-missing until the approved fetch is complete. Preserve the failure transcript.

## PowerShell manual end-to-end

After successful build, execute commands separately (inspect $LASTEXITCODE after every invocation):

    $bin = Join-Path (Get-Location) "target\debug\openscion.exe"
    $repo = Join-Path $env:TEMP ("openscion-cas-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $repo
    New-Item -ItemType Directory -Path (Join-Path $repo "src")
    [IO.File]::WriteAllBytes((Join-Path $repo "src\main.rs"), [Text.Encoding]::UTF8.GetBytes("fn main() {}" + [char]10))
    & $bin init $repo
    $LASTEXITCODE
    $blobResult = & $bin blob put --json $repo "src/main.rs" | ConvertFrom-Json
    $blobResult
    $blobId = $blobResult.id
    & $bin blob verify --json $repo $blobId
    $LASTEXITCODE

Inspect the actual on-disk stored bytes and cryptographic objects:

    $digest = $blobId.Substring(3)
    $blobFile = Join-Path $repo (".openscion\objects\b1\" + $digest.Substring(0,2) + "\" + $digest)
    Get-Item -Force $blobFile | Format-List FullName,Length,Attributes
    Format-Hex -Path $blobFile
    Get-FileHash -Algorithm SHA256 -Path $blobFile
    Get-FileHash -Algorithm SHA256 -Path (Join-Path $repo "src\main.rs")

The raw file SHA-256 is **not the ObjectId**, because ObjectId uses domain separation and the length prefix. Use an independent Python hashlib oracle or equivalent to verify SHA-256("openscion.blob.v1" + NUL + u64_BE(length) + bytes) equals the digest suffix. Record both calculations and source bytes.

Create and inspect the manifest and snapshot:

    $manifest = "src/main.rs" + [char]9 + $blobId + [char]9 + "0" + [char]10
    [IO.File]::WriteAllBytes((Join-Path $repo "manifest.tsv"), [Text.Encoding]::UTF8.GetBytes($manifest))
    $snapshotResult = & $bin snapshot put --json $repo "manifest.tsv" | ConvertFrom-Json
    $snapshotResult
    $snapshotId = $snapshotResult.id
    & $bin snapshot show --json $repo $snapshotId
    $LASTEXITCODE
    & $bin snapshot materialize --json $repo $snapshotId (Join-Path $repo "restored")
    $LASTEXITCODE
    Get-FileHash -Algorithm SHA256 -Path (Join-Path $repo "restored\src\main.rs")
    & $bin snapshot materialize --json $repo $snapshotId (Join-Path $repo "restored")
    $LASTEXITCODE

Expected: stable b1_/s1_ IDs of 67 bytes, 0 exit on valid put/show/verify/materialize, restored bytes match source; repeating materialization must fail E_ALREADY_EXISTS without overwrite.

Negative tests:

    [IO.File]::WriteAllBytes($blobFile, [Text.Encoding]::UTF8.GetBytes("tampered"))
    & $bin blob verify --json $repo $blobId
    $LASTEXITCODE
    & $bin snapshot show --json $repo $snapshotId
    $LASTEXITCODE
    & $bin blob put --json $repo "src/../main.rs"
    $LASTEXITCODE
    & $bin blob put --json $repo ".openscion/format"
    $LASTEXITCODE

Expected: E_OBJECT_CORRUPT for blob verification and snapshot reference verification; unsafe paths must reject with E_UNSAFE_PATH; no corrupt object is repaired or silently overwritten.

## Unix/Linux smoke tests

    root="$(mktemp -d)"
    mkdir "$root/src"
    printf 'fn main() {}\n' > "$root/src/main.rs"
    ./target/debug/openscion init "$root"
    ./target/debug/openscion blob put "$root" src/main.rs
    # Copy exact b1_ ID from output; never guess the digest.
    ./target/debug/openscion blob verify "$root" "$blob_id"
    printf 'src/main.rs\t%s\t0\n' "$blob_id" > "$root/manifest.tsv"
    ./target/debug/openscion snapshot put "$root" manifest.tsv
    ./target/debug/openscion snapshot show "$root" "$snapshot_id"
    ./target/debug/openscion snapshot materialize "$root" "$snapshot_id" "$root/checkout"
    cmp "$root/src/main.rs" "$root/checkout/src/main.rs"
    sha256sum "$root/src/main.rs" "$root/checkout/src/main.rs"

Copy and inspect generated IDs from individual commands. Check POSIX metadata directory 0700 and blob/staged file 0600 as applicable, symlink shard/source refusals, duplicate identical writes and orphan staging behavior. Interrupt publication deliberately on an isolated test fixture and verify no digest-named partial object; record raw observations.

## Windows-specific mandatory gate

On Windows NTFS with actual Rust 1.85.1 and appropriate DACLs, execute PowerShell steps and also:
- Create a junction using mklink /J into an external disposable folder; attempt both source ingestion and destination materialization through it.
- Try Windows symlinks (where allowed), drive-relative strings such as C:relative, reserved device basenames, casefold aliasing, and long paths.
- Observe inherited DACLs of metadata and object files; owner-only confidentiality is **not** certified merely by the Unix 0700/0600 tests.
- Inspect volume hard-link support and process-kill during object staging; restart and verify no partial final object.
- Record failures as actual gaps requiring code corrections, not as expected-pass placeholders.

## Review and gate

Attach command-by-command stdout, stderr, return codes, test fixture hashes, source SHA, golden SHA-256 and snapshot bytes, dependency lockfile/license report, signed review. No merge into main until PR #2 is qualified and both PRs pass required blocking tests on the target platforms.

## Additional Unix CAS privacy regression

After publishing a blob in a disposable Linux test repository, identify the actual on-disk digest file and its parent shard from the printed blob ID. Do not replace a production file.

    chmod 666 "$blob_path"
    ./target/debug/openscion blob verify --json "$root" "$blob_id"
    echo "exit=$?"
    chmod 600 "$blob_path"
    chmod 777 "$(dirname "$blob_path")"
    ./target/debug/openscion blob verify --json "$root" "$blob_id"
    echo "exit=$?"
    chmod 700 "$(dirname "$blob_path")"
    ./target/debug/openscion blob verify --json "$root" "$blob_id"
    echo "exit=$?"

Expected: permissive file mode and permissive shard mode each fail E_UNSAFE_PATH (3) without changing stored bytes or permissions; restoring private modes permits digest-verified reads. These tests do not certify same-user race resistance or Windows DACL protection. Record command-by-command outputs and byte hashes.


## Snapshot resource-exhaustion negative gates

SPEC-002A enforces at most 4,096 regular-file entries and 64 MiB total
materialized bytes per snapshot (a repeated blob referenced N times counts N
times). The tests named
snapshot_entry_count_is_bounded_before_serialization and
repeated_large_blob_references_cannot_amplify_snapshot_materialization
must be individually observed with cargo test --test object_contract -- --nocapture.

Inspect that the excess entries are rejected with E_OBJECT_SIZE, that no
new snapshot digest file has appeared, and that any preexisting objects remain
unchanged. The 64 MiB aggregate limit is deliberately conservative for the
single-machine M1 MVP; it is not a performance claim for distributed use.
