# FOSS-389 — Independent reference-vector cross-check

Date: 2026-10-16 America/New_York (UTC execution 2026-10-17)

## Scope
Verified **serialization/hash reference fixtures only** using Python 3 standard-library hashlib and explicit big-endian decoders. This is NOT a Rust compilation, unit test, filesystem, Windows, concurrency, or recovery test.

## Results
- 26 of 26 independent reference checks passed.
- SPEC-002A: blob digest values for empty, abc, hello world, A, B; empty snapshot and two-file snapshot digests; magic/count, canonical path order, blob references.
- SPEC-003: root/child proposal and revision hashes, snapshot bindings, actor and intent byte-field agreement, root/child parent bindings, and proposal-to-revision references.
- Fixture metadata correction: SPEC-003 root proposal intent had a literal backslash+n while its canonical bytes and Rust test contain an actual LF. Corrected the JSON intent field. No canonical hex or digest change.

## Locally generated independent artifacts
- reference_oracle_report.json SHA256: aa3098d1983fa803482a5067d8b613d225c5e734b81bbfa6c8d97786f58a905b
- spec003_golden_corrected.json SHA256: ddf75a318aa72c6ebaa7637e75bfd41a72b44b50f24d820bb7a2a1ada612a0bb
- toolchain_preflight_2026-10-16.txt SHA256: 590632c5743c8b2099e3b90226b434d0eb6931f31be772bc85af80a0549b0700

Local preflight outcome: rustc, cargo, rustup all absent (exit 127), DNS cannot resolve Rust distribution or GitHub. Cargo build/test/fmt/clippy cannot execute in the current environment. Windows native tests, power-loss tests and independent approval are NOT_RUN.

## Decision
No Rust functionality certified. PRs #2, #3, #4 must remain DRAFT until real manual validation is performed on provisioned Linux/Windows hosts, dependencies audited and reviewed. GitHub Actions not used.
