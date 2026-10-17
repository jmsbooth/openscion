# FOSS-477 — Isolated redb 2.6.4 persistence qualification

**Status:** Evaluation spike only; not OpenScion production code, not an accepted storage ADR, and not part of the root Cargo workspace. All simulated receipt strings are deliberately **unsigned and unhashed** and cannot authorize a revision.

## Why this exists

OpenScion pins Rust 1.85.1. The redb 2.6.4 upstream manifest declares minimum Rust 1.85; the current redb 4.x requires a newer compiler. This isolated crate uses redb **exactly 2.6.4** and its committed `Cargo.lock`, without adding redb to any OpenScion production crate.

## Manual setup / TDD evidence

Run separately on an approved Linux GNU workstation (no GitHub Actions). GNU/glibc is required for this specific invocation; where no native `cc` linker exists, set `CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER` to a working `zig cc` wrapper.

```sh
rustc --version
cargo --version
cargo fetch --locked --manifest-path qa/spikes/redb-264/Cargo.toml
cargo fmt --manifest-path qa/spikes/redb-264/Cargo.toml -- --check
cargo clippy --manifest-path qa/spikes/redb-264/Cargo.toml --locked --offline \
  --target x86_64-unknown-linux-gnu -- -D warnings
cargo build --manifest-path qa/spikes/redb-264/Cargo.toml --locked --offline \
  --target x86_64-unknown-linux-gnu
python3 qa/spikes/redb-264/run_eval.py \
  --binary qa/spikes/redb-264/target/x86_64-unknown-linux-gnu/debug/osc-redb-eval \
  --artifacts /tmp/osc-redb-manual-qa
```

The Python verifier launches disposable subprocesses, holds the write transaction before and after **Durability::Immediate** commit using a scratch-only barrier, actually sends SIGKILL, reopens the DB in a new process, and checks all logical records. Never use the fixture paths for real repository metadata.

## 2026-10-17 observed Linux run

- Rust 1.85.1: cargo build, Rustfmt, Clippy with `-D warnings` and Cargo tests completed without errors.
- 10 kills immediately **before** redb commit: restart saw empty head, seq=0, receipts=0, idempotency=0.
- 10 kills **after** successful durable commit but before response: restart saw head=r1_candidate, seq=1, receipts=1, idempotency=1; identical retry returned prior receipt and changed fingerprint was rejected.
- Thread contention experiments using a single DB authority with **2**, **20** and **100** concurrent callers each yielded exactly one committed head and N−1 expected-head conflicts. Receipt/sequence/idempotency counts remained exactly 1.
- The point-in-time OSV QueryBatch result for redb 2.6.4 and libc 0.2.191 returned **no reported advisories** on 2026-10-17. This is not security certification.
- Raw aggregate run records are preserved in `evidence-summary.json`, original run SHA-256 `62d47e1807772ec486b91cd765f5d96d88c3c6bc9c09c49336f3099de65d5e5c`. Evaluated Cargo.lock SHA-256 `804523ee98f95aa3f30f84ecd320786e0b247e78da0d3a2d9c091cc7ef552b1c`.

## Why ADR-0004 remains PROPOSED

This spike intentionally does **not** implement verified actor authentication, signed policy decisions, separate trusted evidence authorization, schema migration, multi-process authority ownership, cryptographically linked receipts, cross-node consensus, external anchoring, effective ACL validation, Windows NTFS, actual power-loss durability or throughput SLOs. Its single-process thread contention test is not a split-brain/multi-process lock test.

Before promotion implementation (FOSS-479), complete prerequisites FOSS-397/398/465, approve independent evidence verifier profile (FOSS-478), audit exact redb transitive dependency safety/maintenance/migration path, obtain independent storage/security review, and run native Windows/Linux crash/durability qualification. redb 2.6.4 remains **a compatibility candidate**, not a silent dependency approval.
