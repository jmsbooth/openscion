# FOSS-389 — Manual proposal/revision qualification

Current status: NOT_RUN / BLOCKED. Parent FOSS-387 and FOSS-388 manual qualification and independent review are prerequisites. Rust 1.85.1, approved dependency lockfile, and reviewed raw test evidence required. Do not use GitHub Actions.

## Exact Rust commands (run separately; record output and exit codes)

    git rev-parse HEAD
    rustc --version
    cargo --version
    cargo test -p openscion-core --test proposal_contract --locked --offline -- --nocapture
    cargo test -p openscion-cli --test proposal_cli_contract --locked --offline -- --nocapture
    cargo test --workspace --locked --offline -- --nocapture
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets --locked --offline -- -D warnings
    cargo build --workspace --locked --offline

Preserve compiler versions, OS, source SHA, all raw stdout/stderr, named test results and hashes. Rerun every predecessor test; an absent Cargo.lock or uncached crate means BLOCKED, not PASS.

## PowerShell manual scenario

Use a disposable directory only. Inspect each command independently:

    $bin = Join-Path (Get-Location) "target\debug\openscion.exe"
    $root = Join-Path $env:TEMP ("openscion-revision-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $root
    & $bin init $root
    $LASTEXITCODE
    [IO.File]::WriteAllBytes((Join-Path $root "empty.tsv"), [byte[]]@())
    $snap = & $bin snapshot put --json $root empty.tsv | ConvertFrom-Json
    $snap
    [IO.File]::WriteAllBytes((Join-Path $root "intent.txt"), [Text.Encoding]::UTF8.GetBytes("Initial baseline"))
    $p = & $bin proposal create --json $root root $snap.id agent_a intent.txt | ConvertFrom-Json
    $p
    & $bin proposal show --json $root $p.id
    $LASTEXITCODE
    $r = & $bin revision create --json $root $p.id | ConvertFrom-Json
    $r
    & $bin revision show --json $root $r.id
    $LASTEXITCODE
    & $bin revision ancestry --json $root $r.id
    $LASTEXITCODE

Expected: p1_ and r1_ IDs with 64 hex digest characters; actor_verified:false and promoted:false. One-element root ancestry; no main/channel pointer ever created.

Create concurrent candidates from the same root:

    [IO.File]::WriteAllBytes((Join-Path $root "intent.txt"), [Text.Encoding]::UTF8.GetBytes("Agent A update"))
    $pa = & $bin proposal create --json $root $r.id $snap.id agent_a intent.txt | ConvertFrom-Json
    $pa
    [IO.File]::WriteAllBytes((Join-Path $root "intent.txt"), [Text.Encoding]::UTF8.GetBytes("Agent B update"))
    $pb = & $bin proposal create --json $root $r.id $snap.id agent_b intent.txt | ConvertFrom-Json
    $pb
    $ra = & $bin revision create --json $root $pa.id | ConvertFrom-Json
    $ra
    $rb = & $bin revision create --json $root $pb.id | ConvertFrom-Json
    $rb
    & $bin revision ancestry --json $root $ra.id
    $LASTEXITCODE
    & $bin revision ancestry --json $root $rb.id
    $LASTEXITCODE

Expected distinct candidate IDs and ancestry [ra,root] and [rb,root], no implicit merge or promotion.

## Manual negative tests and evidence

- Change one on-disk proposal/ancestor revision byte; digest verification must refuse subsequent read, descendant proposals and ancestry.
- Supply a blob ID instead of revision as base, missing base, missing candidate snapshot, and malformed identifier; verify typed error and no source mutation.
- Try actor claim with traversal punctuation, intent file with NUL/CR, and overlong intent. Confirm default deny.
- Independently compute SHA-256 with the proposal/revision domain prefix, zero separator, u64_BE payload length and canonical bytes; verify p1/r1 IDs.
- Test quotes, backslashes, tabs and LF in intent JSON output for valid escapes; actor_verified must remain false.
- Snapshot digest and metadata marker should remain byte-for-byte unchanged after any candidate operation.
- Stress bounded ancestry depth (4096) and ensure no recursive stack exhaustion or acceptance of corrupt ancestors.
- Execute Windows native build, path and source-control regression scenarios on a Windows workstation.

## Gate

FOSS-389 and its draft PR cannot merge while FOSS-397/FOSS-398 parent qualifications remain incomplete, or without complete manual RED/GREEN execution, cargo fmt/clippy, dependency audit and independent code/security review.