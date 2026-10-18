# M1-Q2 — Native Windows qualification and integration

**Status: tooling implemented, native Windows NOT_RUN, independent security approval NOT_OBTAINED.** FOSS-484 remains open. This document does not authorize merging PRs #2–#4 or integrating verifier PR #6.

## Purpose

The Windows-only M1-Q2 qualification orchestrator is located at qa/qualification/m1_q2_native.py. It uses the independently merged FOSS-488 evidence.py utility to capture one immutable case directory per command, including raw stdout/stderr, command exit status, exact Git SHA and SHA-256 artifact inventories. No GitHub Actions are used.

Before any execution, it rejects unsupported hosts, nonfixed/non-NTFS output volumes, mismatched SHA, dirty Git checkout, missing Cargo workspace, reused packet directories and missing native Windows suites on the CAS/revision branches. Each PR must be tested separately at its exact current head, and again on the final post-merge tree.

On native Windows, it executes Cargo metadata, fmt, workspace tests, Clippy with warnings denied, Cargo build, CLI status-before-init/init/status, and for CAS/revisions the draft branch's PowerShell NTFS/DACL/junction/concurrency acceptance script. Commands run with locked offline Cargo dependencies. A Cargo-generated and reviewed Cargo.lock is required, including on PR #2; absent lockfiles must be corrected and retested, not waived.

## Required Windows setup

Use a trusted native Windows 10/11 or Server workstation, a local fixed NTFS volume, PowerShell 7.4+, Python 3.11+, Rust 1.85.1 Cargo/Rustfmt/Clippy/MSVC, Git and a prepared offline crate cache. Create separate clean worktrees for each PR and an existing evidence parent folder outside those worktrees. Do not substitute WSL, Wine, SMB/network paths or Windows cross-target compilation.

Run the orchestrator from a clean MAIN checkout outside the PR worktrees, substituting your actual paths:

    $tool = 'C:\source\openscion-main\qa\qualification\m1_q2_native.py'
    $repo = 'C:\source\openscion-pr2'
    $sha = (git -C $repo rev-parse HEAD).Trim()
    python $tool --repo $repo --expected-sha $sha --suite cli --output 'C:\m1-evidence\pr2-cli'

    $repo = 'C:\source\openscion-pr3'
    $sha = (git -C $repo rev-parse HEAD).Trim()
    python $tool --repo $repo --expected-sha $sha --suite cas --output 'C:\m1-evidence\pr3-cas'

    $repo = 'C:\source\openscion-pr4'
    $sha = (git -C $repo rev-parse HEAD).Trim()
    python $tool --repo $repo --expected-sha $sha --suite revision --output 'C:\m1-evidence\pr4-revisions'

The PowerShell native test runner now requires SourceRoot and ExpectedHead, rejects existing evidence directories and local non-NTFS hosts, bounds concurrent child waits and records ACL inspection failures. It is present on PRs #3/#4, not PR #2.

## Strict release boundary

A successful local packet is NOT third-party security attestation. It cannot prove genuine host identity, signed build provenance, independent review, true power-loss survival or resistance to a local privileged adversary. The PowerShell runner does not instrument Windows crash/restart at exact commit boundaries; such tests remain NOT_RUN until separately executed.

Release gates remain:
- Real Windows NTFS creation/effective DACL, Everyone Modify rejection, reparse/junction, casefold and no-overwrite observations
- Genuine Windows process-kill/restart recovery at publication boundaries, with raw evidence and source/binary hashes
- Independent human security review and a verifiable APPROVE/REJECT/HOLD disposition on the exact tested source
- Reconcile/qualify/merge PR #2, then PR #3, then PR #4; rerun Linux and Windows verification on post-merge main
- FOSS-487 independent authority/agent identities and pathname TOCTOU remediation before any trusted agent-facing promotion

Run the operator tooling's Linux negative-contract tests with:

    python3 -m unittest discover -s qa/qualification -p 'test_*.py' -v
    python3 -m py_compile qa/qualification/m1_q2_native.py

These tests verify preflight fail-closed behavior only; they are not native Windows qualification.


## M1-Q2B — Windows observational process-kill/restart experiment (FOSS-490)

The optional Windows-only crash observation harness \`qa/qualification/m1_q2_crash.py\` performs repeated **fresh process** blob writes, terminates some writers at multiple delays, retries each unique 1 MiB blob in a new process, and re-verifies the resulting typed object ID and byte length. By default it runs 64 attempts. It uses no GitHub Actions and leaves raw attempt streams and \`summary.json\` for review.

This experiment is not deterministic injection at the precise write/fsync/publish boundaries. A killed process may not have entered a storage syscall. Therefore even an exit-zero run **DOES NOT satisfy** all Windows fault-boundary or power-loss requirements of FOSS-484; it is supplementary recovery evidence.

Use a trusted checkout of \`main\` for the helper scripts and a *separate*, clean checked-out PR #3 or PR #4 revision for the Rust binary. Build the native Windows executable using the M1-Q2 driver first. From PowerShell:

    $trusted = 'C:\source\openscion-main\qa\qualification'
    $repo = 'C:\source\openscion-pr3'
    $sha = (git -C $repo rev-parse HEAD).Trim()
    $binary = Join-Path $repo 'target\debug\openscion.exe'
    $parent = 'C:\m1-evidence'
    $packet = Join-Path $parent 'pr3-interruption-packet'
    $raw = Join-Path $parent 'pr3-interruption-raw'
    $fixture = Join-Path $parent 'pr3-interruption-fixture'
    python (Join-Path $trusted 'evidence.py') capture --repo $repo --source-sha $sha --case windows-interruption --output $packet --artifacts $raw --timeout 1200 -- python (Join-Path $trusted 'm1_q2_crash.py') --repo $repo --binary $binary --expected-sha $sha --artifacts $raw --fixture $fixture --attempts 64

The parent directory must exist on a local fixed NTFS volume. Packet, raw and fixture paths must be nonexistent and outside the PR checkout; no reparse/junction ancestors. Repeat separately for PR #4 and on the final integration SHA. The evidence utility writes the SHA-256 manifest and refuses unexpected exit. A real independent reviewer must inspect the raw observations, executable-build provenance, NTFS ACL and junction cases, exact publication-boundary injections (separate work), and remaining unsupported failure modes.

Linux preflight and fake-CLI integration tests:

    python3 -m unittest discover -s qa/qualification -p 'test_m1_q2_crash.py' -v

Those tests prove helper mechanics, not native NTFS correctness, Windows crash safety or release authorization.
