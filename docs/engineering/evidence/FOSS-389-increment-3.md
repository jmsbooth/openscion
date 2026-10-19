# FOSS-389 — Proposal/revision implementation evidence (2026-10-16)

## Scope and provenance

- Dependency chain: FOSS-387 draft PR #2 -> FOSS-388 draft PR #3 -> FOSS-389 draft PR #4. None are merged or runtime-qualified.
- Independent specification before implementation: commit 39cac14545273f69bdd6fbb150ff7a75061fbae5.
- Library contract cases committed before implementation: b769db5fa933557f45c47f0bbdbe829ee5e524c0.
- First proposal/revision implementation: a3a2cbdf4eba5d0b3ed210599e826fe180a0dfb8.
- Added corrupted-grandparent negative test and changed ancestry implementation from shallow/recursive dependent checking to bounded, iterative, full-chain validation.
- Golden p1/r1 reference vectors computed independently using Python hashlib and structured big-endian encoding. See docs/specs/SPEC-003-golden-vectors.json. The reference artifact SHA-256 on the execution host was 4bd584900607f2c93317ee9559a18825aeb4aa67a116108ba7d44b7e18f501fc.

## Static source inspection

19/19 source-presence checks passed across relevant branch refs (PR #2, PR #3, PR #4): no-overwrite marker, no-overwrite object, Linux/Windows destination publication functions, canonical snapshot decoding, typed proposal/revision SHA-256 domains and limits, JSON escaping, unverified actor disclosure, bounded ancestry, corrupt ancestor tests, golden hash fixture expectations and specs. These check for presence and relationships of source constructs ONLY; they do not establish Rust parsing, compilation, execution, security assurance or functional correctness.

FOSS-389 contains 12 core and 4 CLI Rust test functions at the time of inspection (16 newly authored), with **zero tests compiled or executed**. Actual RED/GREEN phases were not observed.

## Manual execution environment

Observed 2026-10-16T20:03:48Z: Linux 6.18.44 x86_64; git 2.47.3; rustc, Cargo and Rustup unavailable (command-not-found, exit 127). DNS to static.rust-lang.org and github.com unavailable in execution container; no cached .deb Rust packages were found. No GitHub Actions jobs were run by this work.

## Gate states

| Requirement | State |
|---|---|
| Original spec and negative tests authored before change implementation | SOURCE COMPLETE |
| GitHub source read-back assertions | 19/19 STATIC_PASS (not executable) |
| Reference SHA-256 vectors checked independently with Python | REFERENCE_PASS (not Rust) |
| Rust build and tests for PRs #2/#3/#4 | BLOCKED — no compiler/Cargo/dependencies |
| cargo fmt / clippy / Cargo.lock | BLOCKED |
| Windows path, NTFS hardlink, DACL and reparse tests | NOT_RUN |
| Concurrency, race and process-kill recovery | NOT_RUN |
| Independent human/security code review | PENDING |
| GitHub Actions | NOT USED (user requirement) |
| Merge to main | PROHIBITED until mandatory gates pass |

## Risks

- Actor identity in proposals is unverified; not safe for review or promotion decisions.
- Single-parent revision ancestry v1 is not a multi-parent merge DAG and has a depth bound of 4096. Later scale will require indices.
- Local user-visible output may disclose intent text by design; treat untrusted intent content as sensitive.
- The underlying file operations are still not proven safe against a malicious same-user process racing every directory ancestor. Windows reparse/DACL behavior requires native tests.
- The RustCrypto sha2 dependency and its transitive crates require actual Cargo.lock creation, signature/hash verification, license/SBOM and security inspection.
- The implementation has no mutable authoritative channel, policy evaluation, transactionally consistent promotion, signed attestations, or rollback.

**Decision:** Keep FOSS-389 in progress and PR #4 in draft. Do not merge this or its predecessors until executable and independent security gates are evidenced.