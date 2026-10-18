# M1-Q1 — Local qualification evidence capture (FOSS-488)

**Status: QA integrity tooling only. Does not certify M1, native Windows execution, identity, reviewer independence, or security correctness.**

## Purpose and trust boundary

The standalone Python 3.11+ standard-library helper at qa/qualification/evidence.py preserves exact-commit, individually executable test transcripts and optional raw fixture files for offline inspection. This is an **untrusted packaging tool**: an actor able to change a packet can recompute the included SHA-256 manifest. A clean-tree Git HEAD records the source revision; it does not authenticate the operator or attest native operating system identity. Independent security review, native-host inspection, signed provenance, and approved governance remain separate release prerequisites.

Nothing in this increment changes a protected channel, an authoritative object store, receipt, promotion or rollback logic. No GitHub Actions are invoked.

## Contract

- Capture requires a 40-character lowercase Git HEAD SHA, clean checkout at that SHA, and an existing evidence parent directory outside the source checkout. Existing case directories cannot be overwritten.
- Executes explicit argv directly without a shell, with finite timeout and raw stdout/stderr capture. Negative tests may declare an expected nonzero exit using --expect-exit.
- Records source SHA before and after, clean-tree observations, self-reported OS and Python versions, command, timestamps, expected and actual exit, and timeout.
- Copies optional raw files from an existing --artifacts directory, rejecting symbolic links, junctions and non-regular files. Caps artifact count and size. SHA-256 and byte counts are recorded per file.
- Offline verify rejects missing cases, missing/altered logs, duplicate JSON keys, schema mismatches, wrong SHA or required platform, unexpected exits, and timed-out cases.
- Passing verification emits status=integrity_valid, independent_review=not_assessed, native_platform_attestation=not_provided. This is never release approval.
- Run only trusted commands on disposable fixtures; subprocesses inherit local identity and environment, and this utility does not redact secrets or isolate processes.

## Linux operator example

Run from a clean checkout at the exact revision to qualify. Capture each test case separately:

    mkdir -p /tmp/openscion-m1-evidence
    SHA=$(git rev-parse HEAD)
    python3 qa/qualification/evidence.py capture --repo . --source-sha "$SHA" --output /tmp/openscion-m1-evidence/rust-format --case rust-format -- cargo fmt --all -- --check
    python3 qa/qualification/evidence.py capture --repo . --source-sha "$SHA" --output /tmp/openscion-m1-evidence/rust-tests --case rust-tests --timeout 1200 -- cargo test --workspace --locked --offline -- --nocapture
    python3 qa/qualification/evidence.py verify --packet /tmp/openscion-m1-evidence --source-sha "$SHA" --require rust-format:Linux --require rust-tests:Linux

## Native Windows procedure (NOT_RUN)

Use PowerShell 7.4+, native Rust 1.85.1 and a disposable NTFS fixture, following qa/windows/README.md and M1-Qualification.ps1 on the reviewed PR revision. Precreate the evidence packet directory but honor the Windows script's own artifact directory preconditions.

    $sha = (git rev-parse HEAD).Trim()
    $packet = Join-Path $env:TEMP 'openscion-native-m1-evidence'
    New-Item -ItemType Directory -Force -Path $packet | Out-Null
    $raw = Join-Path $env:TEMP 'openscion-native-m1-raw'
    python qa/qualification/evidence.py capture --repo . --source-sha $sha --output (Join-Path $packet 'windows-ntfs') --case windows-ntfs --timeout 1200 --artifacts $raw -- pwsh -NoProfile -File qa/windows/M1-Qualification.ps1 -Binary (Resolve-Path '.\target\debug\openscion.exe').Path -SourceRoot (Resolve-Path .).Path -ExpectedHead $sha -ArtifactDir $raw -Contenders 20
    python qa/qualification/evidence.py verify --packet $packet --source-sha $sha --require windows-ntfs:Windows

The Windows command has not been executed during this increment. Its completion alone cannot satisfy FOSS-484: separate native crash/restart testing and independent security review are mandatory. An OS name in JSON is not an attestation. Re-run and inspect on the exact head of each qualified PR, including after merges.

## TDD, scope, and release gate

    python3 -m unittest discover -s qa/qualification -p 'test_*.py' -v

Contract tests cover expected and unexpected exits, exact SHA and dirty tree, duplicate IDs, wrong-platform requirements, modified raw logs, malformed/duplicate metadata keys, symlinked artifacts and logs, missing artifacts and timeout failure. Run commands separately and retain raw transcripts on an authorized host. An independent reviewer must inspect actual native DACL, junction, durability, identity and source behavior, and sign qa/windows/INDEPENDENT-REVIEW.md.

FOSS-484, FOSS-397/398/465, and FOSS-487 remain unwaived. Do not merge PRs #2, #3, #4 or integrate the verifier PR #6 solely because this utility reports integrity_valid.
