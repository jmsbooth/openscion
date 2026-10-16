# OpenScion roadmap — draft 0.1 (2026-10-16)

## Mission
Build an independent, secure source-control and change-management substrate designed for many concurrent software-development agents. The first acceptance target is **one machine / one repository / multiple independent proposals**. Distribution is a subsequent milestone.

## First principles
1. **Proposal is not promotion.** Agent work never silently moves stable state.
2. **Content is immutable.** Bytes and canonical object types determine digest-addressed IDs. Prevent type confusion with domain separation.
3. **Mutable pointers are tiny and guarded.** Stable channel heads move only under optimistic concurrency and approved, evidenced policies.
4. **Provenance is a trust claim that must be verifiable.** Agent-reported identities, tests and approvals alone are untrusted claims.
5. **Undo is forward-only.** Rollback creates a new promotion event against a known verified prior artifact.
6. **Workspaces are disposable.** Logical revisions, checks and retrieval work without requiring a fully cloned repository.
7. **Start simple and measure.** Single-node reliable store first; partitioned storage, network caching and scale after validation.

## Prior art and independently chosen differentiators
Git provides dependable immutable histories and broad interoperability but clones and globally coordinated integration points can be burdensome at extreme scale. Anthropic described a server-centric, incremental source-control system in a **public engineering article** on 2026-10-13, updated 2026-10-15. OpenScion does not implement its private design. Other public prior art includes Git, Jujutsu, Sapling/Mononoke, content-addressed storage, in-toto, and SLSA. These are **research context**, not code to reproduce.

**OpenScion focus:** an explicit agent *intent/proposal/evidence/decision/promotion* lifecycle; protected policy scopes and time-bounded agent delegation; verifiable evidence, reversible releases; machine-queryable provenance; optional Git gateway.

## Milestones and exit criteria
### M0 — Independent architecture / SDD
- Approved problem statement, original specification, functional/nonfunctional requirements and terminology.
- Dated research/origin register and source-use policy; IP/trademark review tracked as unresolved.
- Threat model includes compromised agent, colluding reviewer, poisoned artifact, stale head, crash/recovery, tenant escape, credential replay and audit tampering.
- Tests and traceability matrix authored before implementation.

### M1 — Local Rust baseline
- CLI operations: `init`, `add/propose`, `show`, `verify`, `gate`, `promote`, `rollback`, `materialize`.
- Canonical manifest and cryptographic digest verification, immutable candidate objects, expected-head guarded promotion.
- Durability (atomic persisted update), restart/recovery handling, stale-head denial, path validation and tamper detection.
- A negative test must prove that lacking independent gate evidence cannot change stable state.
- All local manual test runs recorded with exact commands/output, source SHA, environment, expected/actual result and raw artifact hashes.

### M2 — Concurrent trust/control
- Verified workload identity rather than self-asserted actor fields; delegation expiry and scoped permissions.
- Independent human/agent approval policy; code policy, signed attestations, audit receipts and replay defense.
- Property-based tests and reproducible race simulations.

### M3 — Networked service and sparse retrieval
- Independently specified authenticated network API; range/path-scoped object access and quotas.
- Tiered content cache and stateless query frontends; retry/idempotency, no cache-to-authority cascading failure.
- Sparse and on-demand materialization; measured concurrency/memory/network performance.

### M4 — Release-readiness and interoperability
- Optional Git migration and export bridge; lineages preserved with original proof-verification status.
- SBOM, dependency/license validation, fuzz and fault-injection evidence, reproducible builds, independent security and IP review.
- Versioned protocol, migration guide, performance report and signed release artifacts.

## Decisions / alternatives requiring ADRs
- Snapshot strategy: persistent Merkle trie vs per-revision sorted manifest vs delta-only journal. M1 favors a bounded sorted manifest; switch only with measured need.
- Persistence: append-only log + compact head metadata vs embedded transactional DB. Must prove crash atomicity before M1 acceptance.
- Hash: SHA-256 with typed/domain-separated canonical encodings initially; avoid unreviewed bespoke cryptography.
- Approval model: local signed claims for research vs externally authenticated verification service for trusted production use.
- Concurrency: independent proposals; compare-and-swap guarded channel pointers; no automatic semantic merge initially.
- Availability: local-first M1, always-online server in M3; secure offline inspection remains possible.

## SDD and test-first delivery rule
For every issue: requirements → red tests (unit, negative/security, regression) → minimal implementation → manual execution → evidence archive → independent review → PR. GitHub CI credits are unavailable; **GitHub Checks do not establish acceptance**. A missing local compiler is a blocker, not a pass.

## Scope control
Not a Git clone, not byte-for-byte interoperable with Anthropic, not production ready until M4; no autonomous merges into protected channels, no opaque agent-authored `tests_passed` flag.

## Traceability
Linear FOSS-376–FOSS-384 are the architecture epics. Child stories carry testable requirements and evidence references.
