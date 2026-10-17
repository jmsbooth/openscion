# OpenScion — Native Windows M1 release qualification

**Status:** NOT_RUN on Windows. The Linux GNU/MUSL tests and Windows cross-target `cargo check` do not provide NTFS/DACL evidence.

Run this on a **native Windows 10/11 or Server workstation using NTFS, PowerShell 7.4+ and Rust 1.85.1**. The runner creates a disposable fixture underneath the selected artifact directory. It deliberately adds and then restores permissive ACL entries on fixture files to test fail-closed behavior. Never target production repositories. No GitHub Actions.

## Prerequisite commands — inspect individually

```powershell
git rev-parse HEAD
rustc --version
cargo --version
rustup show active-toolchain
cargo metadata --locked --offline --format-version 1
cargo fmt --all -- --check
cargo test --workspace --locked --offline -- --nocapture
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
cargo build --workspace --locked --offline
Get-FileHash -Algorithm SHA256 -Path Cargo.lock
```

Resolve reviewed Cargo dependencies explicitly on an approved workstation before using `--offline`. Do not treat absent dependencies as a passed test.

## Native NTFS security and functional evidence

```powershell
$bin = (Resolve-Path .\target\debug\openscion.exe).Path
$evidence = Join-Path $env:TEMP ("openscion-m1-review-" + [guid]::NewGuid().ToString("N"))
pwsh -NoProfile -File qa/windows/M1-Qualification.ps1 -Binary $bin -ArtifactDir $evidence -Contenders 20
$LASTEXITCODE
Get-Content -Raw (Join-Path $evidence 'summary.json')
Get-ChildItem $evidence | Select-Object Name, Length
```

**Expected RED gates on the existing source:** Windows metadata/marker/object permission checks are currently Unix-gated in the Rust code. The script verifies that an `Everyone:Modify` ACE on private store metadata, format marker or blob is rejected. Until FOSS-484 implements protected Windows DACL creation and validation, those tests are expected to fail; **do not waive or record PASS**. Junction/reparse, path traversal, no-overwrite concurrency, bytewise snapshot restore and raw NTFS DACL evidence are also checked.

The script does **not** instrument Windows process crashes at exact publication boundaries, emulate power loss, attest reviewer independence, or validate ReFS/SMB. Those are separate release gates. It exits nonzero if any observed case fails or cannot run, and stores per-command raw output, error logs and hashes. An exit-zero script is never itself an independent security review.

## Independent security signoff

Use the observed result artifacts to review:
- exact PR head and Cargo.lock / binary SHA-256;
- initialized NTFS owner/OS SYSTEM/Administrators access, private DACLs and denied untrusted principals;
- permissive DACL injection and restoration, junction and no-overwrite behavior;
- actual restart/power-loss durability evidence on supported storage;
- source-control trust boundaries, especially remaining same-user TOCTOU exposure;
- reviewer identity, decision, remediation commit SHA and retest.

Do not merge PR #2, #3 or #4 merely because GitHub shows `mergeable`. FOSS-484 (Windows DACL) and native recovery qualification remain mandatory. FOSS-485 (orphan reclamation) is a separate high-scale operational increment.
