# FOSS-388 — Increment 2 development / qualification evidence (2026-10-16)

**Branch:** feat/foss-388-immutable-objects
**Dependency:** FOSS-387, draft PR #2; its executable gate remains blocked.
**Qualification state:** DRAFT / NOT EXECUTED / NOT MERGE READY.

## Provenance and specification

- First requirement contract commit: 3afd7731c844089c6806e416509224dec0a3f7f1.
- First core integration test-source commit (before implementation): c2e45172bb0b6955566f0617e3d7daedc8ed81b6.
- Object identity/path implementation first commit: 08eb037ed5d99716bc12a277bb29297e919143c8.
- Snapshot canonical encoder and parser first commit: 176647f3a78d2bfe7ba972433936066c3b39ca14.
- Store implementation first commit: 8cce78054398e85dcd7f504ff537d7d115ff3a6d.
- Independently computed Python hashlib golden vectors archived at docs/specs/SPEC-002A-golden-vectors.json. The local source artifact SHA-256 was aa539bfbf828d20b417aa2688485ca62094b72cdf3ded66807252c1d1b17c403.
- Actual final source SHA must be recorded when a developer workstation runs qualification; it may have advanced since this file was written.

## Source-level review (NOT executable validation)

GitHub connector read-back confirmed presence of 16 expected files in this branch and examined named source statements for RustCrypto sha2 0.10.9 pin, typed digest identities, strict lower-case hex parser, canonical snapshot order/lengths, portable path validation, hard-link no-overwrite object publication, bounded reads, on-read digest checks, referenced blob verification, staging write/sync, nested directory fsync, and exposed CLI commands. **All 22 defined structural source assertions were observed on manual follow-up**; the initial check reported 21/22 because one assertion incorrectly required two nonadjacent lines to be literally adjacent. Reading the store.rs lines confirmed exclusive file creation occurs before the cleanup guard owns the temporary file. These assertions are only static presence/ordering checks; they do not prove Rust compilation, functional success, race safety, or cryptographic implementation correctness.

## New authored automated tests

- 16 Rust test functions in crates/openscion-core/tests/object_contract.rs (platform-gated cases included).
- 4 Rust test functions in crates/openscion-cli/tests/object_cli_contract.rs.
- Total **20 new functions authored, 0 executed**. Existing FOSS-387 tests on the stacked branch must also be rerun. No observed RED or GREEN phase exists because Cargo/rustc are unavailable.
- Independent Python hashlib produced the two known SHA-256 blob vectors, empty-snapshot vector and two-file canonical manifest digest; this verifies the **reference fixtures only**, not that the Rust implementation produces those results.

## Evidence matrix

| Gate | Outcome |
|---|---|
| Original behavior-only protocol written | SOURCE_COMPLETE |
| Initial core tests committed before code | SOURCE_COMPLETE |
| Reviewed RustCrypto SHA-2 0.10.9 published API and license | DESK_REVIEW (MIT/Apache-2.0; transitive/license audit pending) |
| Static source assertions | 22/22 STATIC (not executable) |
| Golden reference vectors via Python hashlib | REFERENCE_PASS (not Rust) |
| Rust compile, Cargo.lock, offline tests | BLOCKED (rustc/cargo absent; dependencies uncached) |
| 20 new integration tests | NOT_RUN |
| cargo fmt / clippy | NOT_RUN |
| Manual CLI blob/snapshot/materialize inspection | NOT_RUN |
| Concurrent write, corruption, path negative tests | NOT_RUN |
| Windows NTFS DACL/reparse/junction security validation | NOT_RUN |
| Interrupted process / crash-fault injection | NOT_RUN |
| Security dependency audit / SBOM | NOT_RUN |
| Independent code/security reviewer | PENDING |
| GitHub Actions | NOT_USED |

## Known limitations requiring adjudication

1. FOSS-387 is a required parent for FOSS-388; neither is qualified under manual SDD/TDD policy.
2. Object paths are inspected before use, but mutable namespace operations are **not race-free against malicious same-user writers**. Handle-relative/no-follow APIs and a separately authenticated service principal are future security requirements; this is local development storage only.
3. Filesystem hard-link publication depends on volume support, including NTFS behavior. No fallback that overwrites digest names exists.
4. Materialization uses pre-check plus rename. A malicious same-user concurrent directory replacement may race it; a future deployment must use atomic no-replace platform primitives or trusted isolated workspace ownership.
5. On Windows, metadata and object DACL inheritance is not yet proven confidentiality preserving.
6. The crate lockfile and transitive dependencies are not resolved/audited in this isolated executor. RustCrypto sha2 is pinned to an exact published version, but requires lockfile generation, reproducible download, and licensing/vulnerability review.
7. Interrupted-write and recovery behaviors are specified and partially unit-testable through abandoned staging fixtures. Actual process-kill power-loss, cross-filesystem, and Windows tests have not run.
8. No revisions, version branches, source-control provenance, authorization decisions, or safe rollback exist in this increment.

**Decision:** This branch and its dependent PR must remain DRAFT. Do not merge to main or mark FOSS-388 Done until all blocking manual validation evidence is independently examined and filed.
