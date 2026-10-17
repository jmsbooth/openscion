# OpenScion M1 stacked PR merge-readiness review — 2026-10-16 EDT

## Disposition: BLOCKED — DO NOT MERGE

The following GitHub PRs remain draft; they are linked in order:

1. PR #2 (FOSS-387), base main: Rust CLI bootstrap and owner-only metadata.
2. PR #3 (FOSS-388), base FOSS-387 branch: immutable blob/snapshot CAS.
3. PR #4 (FOSS-389), base FOSS-388 branch: unpromoted proposal/revision graph.

The PR #4 branch now has an explicit two-parent stack-reconciliation commit `d845743e638eaeac732786b85fcb921c26286d5a`; the resulting GitHub PR is mergeable from a source-tree perspective. This is **not a qualified software merge**.

## Hardening changes addressed in this review

- PR #2: existing Unix metadata directory and marker permissions validated owner-only; insecure group/world permissions fail closed. Unit tests and manual chmod cases added.
- PR #3: reject nested .git/.openscion path components; object files/shards require Unix-private permissions. Added regression cases.
- PR #3: bound snapshots to 4096 entries and 64 MiB aggregate materialized bytes (repeated references count repeatedly), to prevent I/O and checkout amplification. Resource-exhaustion tests added.
- PR #4: inherited all predecessor code, test, SDD and runbook changes; reconciled the Git history with PR #3 without merging to main.
- PR #4: corrected CLI human messages so unpromoted revisions are not described as absent; additional CLI regression added.
- SPEC-001A and SPEC-002A and associated manual QA procedures updated to reflect new invariants.

## Source-level readback

Connector read-back verified all nine named source invariants across PR #3 and PR #4 and all three private-metadata invariants on PR #2. Branch-diff inspection before the stack merge verified that PR #4 differs from PR #3 only by intended proposal/revision code and documentation.

Authored test function counts:
- FOSS-387 PR #2: 22
- FOSS-388 PR #3: 25
- FOSS-389 PR #4: 17
- Combined: 64 functions in Rust source.
- **Observed Rust executions: zero.** Not a runtime or security pass.

## Actual local toolchain preflight

On Debian GNU/Linux 13 (kernel 6.18.44) at 2026-10-17T01:08:12Z:
- `git --version`: exit 0, version 2.47.3.
- `rustc --version`, `cargo --version`, `rustup --version`: exit 127 (commands absent).
- `cargo test --workspace --offline -- --nocapture`, `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --offline -- -D warnings`, `cargo build --workspace --offline`: exit 127 (Cargo absent).
- DNS to github.com and static.rust-lang.org: exit 2 (unresolved).
- Native Windows host: unavailable.

Local raw transcript:
`/mnt/data/openscion_qualification/openscion_pr2_pr3_pr4_merge_gate_2026-10-16.txt`
SHA-256: `bbefda43635a60717a495c8e0c8ba00138898a3c1a1b84d904e76c64bee42fbc`

**The local transcript is not part of this PR until uploaded by a reviewer; include its hash when attaching.** Earlier preflight records and independent Python reference-vector checks remain separate evidence, not Rust execution.

## Mandatory remaining gates

1. Provision a supported, pinned Rust toolchain and offline dependency cache. Generate and review `Cargo.lock` for sha2 and all transitive crates. Run dependency-license/security/SBOM checks.
2. Execute test-first/negative regressions for each increment separately, then full workspace, with real `cargo test`, `cargo fmt --check`, `cargo clippy -D warnings` and `cargo build`; preserve raw stdout/stderr/exit codes and source SHA.
3. Manually inspect init/status, blob/snapshot storage, corrupted object detection, source-control metadata path denial, exact materialization and proposal/revision ancestry. Archive raw bytes and independent SHA-256 checks.
4. Run native Windows NTFS, junction/reparse, ACL and hard-link tests. Run Unix symlink/private-permission negative cases and crash/process-kill/restart recovery.
5. Independently review safety of path race handling against an agent that can mutate the filesystem under the same user identity; do not represent it as race-free.
6. Record a reviewer acceptance decision and merge PRs #2, #3, #4 sequentially after all applicable gates pass. GitHub Actions credits must not be used.

## Next increment after qualification

FOSS-390: protected channel atomic CAS promotion, independent policy/evidence authorization, immutable receipt and idempotency in a single crash-consistent transaction. Select the transactional backend in an ADR (redb vs SQLite/WAL are candidates); hash-chain and signature guarantees must be independent of any non-cryptographic database checksum. No implementation of FOSS-390 should be merged ahead of these prerequisites.

## Meaning of statuses

`SOURCE_REVIEWED` means code/requirements were inspected. It is **not** `TEST_PASSED`, `RELEASE_APPROVED`, `SECURITY_CLEARED` or `MERGED`.
