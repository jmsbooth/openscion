# ADR-0004 — Single-authority transactional promotion state

**Status:** PROPOSED — not accepted, implemented, or qualified  
**Issue:** FOSS-390  
**Decision scope:** OpenScion M1 local promotion control plane; immutable CAS remains separate  
**Prerequisites:** Qualify/merge FOSS-387 (#2), FOSS-388 (#3), FOSS-389 (#4), in order, after manual Linux/Windows tests and independent security review.

## Decision under consideration

Use a **single-writer embedded ACID database for the authoritative promotion state**. The database must atomically commit:
1. The protected channel's new head, revision sequence and last receipt digest;
2. A canonical immutable promotion receipt, cryptographically linked to the previous receipt;
3. Idempotency key binding to the exact authorized request digest;
4. Version/epoch references required to ensure the approval and policy checks were current for this promotion.

An OpenScion object digest alone does not prove agent identity, authorization or release approval. redb's internal checksums are **not cryptographic provenance**. Approval/evidence signatures, policy enforcement and receipt hash chaining are independent application-layer responsibilities.

**Provisional implementation candidate:** \`redb = "=2.6.4"\`, subject to compatibility, licensing, security and crash testing. **Do not add this dependency or implement protected promotion until the prerequisites pass.** FOSS-390's interface and test cases can be designed now.

## Why 2.6.4 instead of the newest redb

The project pins Rust **1.85.1** in \`rust-toolchain.toml\`.
- Upstream redb \`v2.6.4\` declares \`rust-version = "1.85"\` and Rust edition 2024.
- Upstream redb \`v3.1.3\` declares \`rust-version = "1.89"\`.
- Upstream redb \`v4.4.0\` declares \`rust-version = "1.90"\`; therefore it **cannot be assumed compatible with our pinned toolchain**.
- These facts come from upstream versioned Cargo.toml manifests (checked 2026-10-16), not execution against OpenScion. Pinned-version transitive dependencies and actual Cargo compilation must still be validated.

Upstream sources:
- https://github.com/cberner/redb/blob/v2.6.4/Cargo.toml
- https://github.com/cberner/redb/blob/v3.1.3/Cargo.toml
- https://github.com/cberner/redb/blob/v4.4.0/Cargo.toml
- https://docs.rs/redb/latest/redb/struct.WriteTransaction.html
- https://github.com/cberner/redb/blob/master/docs/design.md

The 2.6.x line is a **compatibility candidate**, not a claim of indefinite upstream support. Before acceptance, compare security advisories, database file-format stability, migration path, transitive crate licenses, lockfile checksums and maintenance policy; otherwise consider an explicit toolchain upgrade to >=1.90 and evaluate current redb 4.x.

## Alternatives and tradeoffs

| Alternative | Strength | Limitations for OpenScion | Initial disposition |
|---|---|---|---|
| redb 2.6.4 | Pure Rust, embedded copy-on-write B+tree, ACID/MVCC model, nominal MSRV 1.85 | Version is older than 4.x; file-format/recovery behavior and security support must be examined | **Provisional preferred** |
| redb 4.4.0 | Current 4.x feature/bug-fix stream, pure Rust | Requires Rust 1.90, inconsistent with current pinned toolchain; toolchain upgrade itself needs full requalification | Evaluate under separate toolchain ADR |
| rusqlite + SQLite WAL | Mature transactional semantics and operational inspection tooling | Native SQLite dependency, C/FFI build/ABI/supply-chain surface, MSRV uncertainty in current releases, WAL checkpoint/recovery discipline | Contingency if redb fails gates |
| Flat JSON/head files + lock | Lowest dependencies | Difficult atomicity across head, receipt, sequence and idempotency; platform race/crash risks; reconstructing a database from scratch | **Reject** |
| Distributed consensus / shared NFS | Eventually useful for decentralization | Leader election/quorum, split-brain, identity and replicated storage are not solved by a local embedded DB | Out of scope until M2+ |

SQLite is public domain and rusqlite is MIT; choose explicit bundled/system dependency and validate exact toolchain. See https://docs.rs/crate/rusqlite/latest/source/README.md .

## Authority and durability invariants

- The **authority database** is the only mutable location for channel heads. Neither a \`p1_\` proposal nor an \`r1_\` revision implies acceptance.
- An agent never opens or writes the authority DB; only the trusted promotion service may hold a write handle. Filesystem owner isolation, application authentication, OS ACLs and Windows reparse/junction testing are mandatory.
- Use redb \`Durability::Immediate\` (or documented equivalent, validated for selected version), never None/Eventual for accepted promotions. Consider return-of-commit vs fsync guarantees on the target filesystem.
- A successful promote operation must commit head + sequence + receipt + idempotency as **one DB transaction**. No filesystem staging/rename sequence substitutes for this.
- No external side effect occurs inside the DB transaction that cannot be rolled back; pre-ingested immutable CAS objects and verified evidence are checked before transaction, and references/epochs/expected head are rechecked inside the serialized authority transaction.
- A cryptographic receipt digest covers canonical, versioned fields and previous receipt digest; no algorithm/downgrade negotiation from untrusted requests.
- DB checksum detects storage faults; keyed signatures/approved cryptographic hashes establish trusted evidence. Separately protect files against OS-admin/same-user mutation and rollback of a copied old database. A single machine cannot prove globally monotonic history without an independent anchor.
- Idempotency lookup is scoped to authenticated issuer + channel + key. Exact same fingerprint returns prior verified receipt (not a second write); different fingerprint is rejected. A previously successful receipt cannot be repudiated by replaying a stale response.
- Channel epochs and trusted policy/evidence revocation epochs are part of the consistency boundary; if authoritative revocation state is unknown, fail closed.
- Unsupported filesystems, insecure directory permissions, multiple leader instances or untrusted clock behavior are explicit errors, not automatic fallbacks.
- Network partitions cannot make a second local writer authorized. Multi-node quorum/replication is future work.

## Explicit rejection of premature guarantees

This ADR does **not** certify redb 2.6.4 under Rust 1.85.1, Windows NTFS, Linux fsync, power-loss behavior, network filesystem semantics, multi-process locks, integrity against a malicious same-UID process, or distributed consensus. Such claims require the acceptance artifacts described in SPEC-004.

## 2026-10-17 runtime compatibility evidence (evaluation only)

A **standalone nested scratch Cargo workspace**, not a production OpenScion dependency, now lives at `qa/spikes/redb-264/`. It was compiled at Rust **1.85.1** using exact `redb = "=2.6.4"` with reviewed `Cargo.lock`. Exact PR #5 head `c2eed69e1372a9250b74215bc0774a9df4bc27d8` passed local `cargo fmt --check`, `cargo clippy -- -D warnings`, Cargo build and 20 subprocess SIGKILL/reopen recovery scenarios. It used `Durability::Immediate` and persisted head, sequence, receipt and idempotency as a single write transaction.

Observed: 10 kills before commit left all four records empty; 10 kills after commit/before response preserved all four, with idempotent retry recovering the same result and changed fingerprint rejected. Thread contenders N=2,20,100 each produced one winner and N−1 expected-head conflicts. Point-in-time OSV QueryBatch checks returned no reported advisories for redb 2.6.4 and libc 0.2.191 on 2026-10-17. Original 23-scenario manifest SHA-256: `62d47e1807772ec486b91cd765f5d96d88c3c6bc9c09c49336f3099de65d5e5c`; evaluated Cargo.lock SHA-256 `804523ee98f95aa3f30f84ecd320786e0b247e78da0d3a2d9c091cc7ef552b1c`. Scratch source, runbook and the manifest are committed.

**Limitations:** no native Windows test, true power-loss test, security audit beyond the point-in-time advisory query, schema-migration test, independent signoff, multi-process authority/locking or issuer signature validation. The scratch receipt is deliberately not a cryptographic proof. The evaluation supports the compatibility candidate but **does not satisfy ADR acceptance criteria** or authorize FOSS-479 implementation.

## Acceptance / reversal criteria

Promote this ADR to **Accepted** only after:
1. All predecessor PRs are locally executed, security-reviewed and merged.
2. Rust toolchain and dependency graph are resolved into reviewed Cargo.lock; \`cargo tree\`, \`cargo deny\`/equivalent licensing & advisory report and SBOM are archived.
3. Both Linux and Windows tests prove one winning CAS, idempotency, durable receipts and crash recovery, including fault injection around transaction commit and process restart.
4. Benchmarked write throughput and recovery time meet documented M1 thresholds (define thresholds from actual agent workload rather than invented capacity).
5. Independent security review signs off storage boundary, signature verification, epoch semantics, ACLs and TOCTOU analysis.

If redb 2.6.4 fails security/maintenance or crash tests, reopen the decision and test SQLite WAL or upgrade the Rust toolchain and evaluate redb 4.x. Never silently substitute an unreviewed backend.
