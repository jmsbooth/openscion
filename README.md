# OpenScion

**Independent, agent-native source control and change governance.** OpenScion is an experimental Rust-based open-source project. It is **not** a clone or implementation of Anthropic Scion, and is not yet a usable revision-control system.

## Why

Agentic development needs an explicit lifecycle for immutable candidate revisions, parallel proposals, verified evidence, narrowly delegated authorities, atomic promotion and audited recovery.

## Status

- **M0 architecture/SDD:** merged into main. See [roadmap](docs/roadmap.md) and [architecture](docs/architecture/v0.1.md).
- **M1 increment FOSS-387:** Rust workspace and dependency-free local CLI bootstrap implemented in a feature PR. Implementation is **pending local runtime tests**; no passing Rust test or production security claim is asserted.
- **M1 next steps:** content-addressed snapshots, revision DAG, gate-bound CAS promotion and forward-only rollback remain unimplemented.

## Dependent M1 increment: FOSS-388

The stacked FOSS-388 implementation (PR #3) introduces:
- Typed, domain-separated SHA-256 object IDs (b1_/s1_).
- Verified immutable blobs with no-overwrite publication and deterministic snapshots.
- Portable regular-file paths, strict canonical manifest format, corruption detection and staged materialization.
- Manual blob/snapshot CLI commands, supported by negative unit and integration tests.

**This increment is NOT QUALIFIED.** The host lacks Rust/Cargo and no Windows runtime checks were run. sha2 0.10.9 is a pinned upstream dependency; Cargo.lock generation and security/license review are outstanding. FOSS-387/PR #2 remains a blocking predecessor.

The new commands, after the toolchain and dependency setup are approved, are:

    openscion blob put <repo> <repo-relative-file>
    openscion blob verify <repo> <b1_ID>
    openscion snapshot put <repo> <repo-relative-manifest.tsv>
    openscion snapshot show <repo> <s1_ID>
    openscion snapshot materialize <repo> <s1_ID> <new-directory>

Manifest lines are path, blob ID and 0/1 executable mode, separated by TABs and terminated with LF. All paths are portable, ASCII-only and repository-relative, with sensitive metadata excluded. Snapshots are content-only objects, not revisions, branches, approvals, or release provenance.

See [SPEC-002A](docs/specs/SPEC-002A-content-addressed-store.md) and [manual FOSS-388 qualification](docs/engineering/foss-388-manual-qa.md) before considering this functionality usable.

## First local commands (when Rust 1.85.1 is installed)

    cargo test --workspace --offline -- --nocapture
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets --offline -- -D warnings
    cargo build --workspace --offline
    ./target/debug/openscion --help
    ./target/debug/openscion doctor --json
    ./target/debug/openscion init ./existing-empty-directory
    ./target/debug/openscion status ./existing-empty-directory

Use "target\debug\openscion.exe" instead of "./target/debug/openscion" on Windows. "init" requires an existing directory and creates an exclusive ".openscion/format" marker. The "status" result "unborn" means **no revisions exist**; it is not evidence of trusted changes.

No source control operations (propose, verify, promote, rollback) are implemented yet. They fail with E_USAGE rather than performing fake operations.

See [SPEC-001A](docs/specs/SPEC-001A-cli-bootstrap.md), [manual test runbook](docs/engineering/foss-387-manual-qa.md), [independent-development protocol](docs/governance/independent-development.md), and [SDD/TDD qualification](docs/engineering/sdd-tdd-manual-validation.md).

## Principles

- Independently designed from publicly observable software-engineering needs; no copied Anthropic source code, private documentation or unpublished protocols.
- Proposals do not change authoritative state; future protected channels advance only under server-controlled authorization and compare-and-swap.
- Content integrity is separate from identity, approvals and trusted attestations.
- Rollback creates a new auditable event; historical revisions are never rewritten to hide an incident.
- SDD/TDD, independently inspected local evidence, and no dependence on GitHub Actions credits.
- Local-first validation before distributed functionality.

## License

MIT. Consult [LICENSE](LICENSE). All third-party code and generated content require their own license and origin review.

## Research disclosure

Anthropic's public article is a background problem statement, not an implementation specification. This implementation is not represented as satisfying a formal two-team clean room. Independent authorship and patent/trademark questions require separate review.
