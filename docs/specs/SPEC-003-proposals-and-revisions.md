# SPEC-003 — Immutable candidate proposals and revisions (draft)

Issue: FOSS-389. This branch is stacked on FOSS-388 PR #3 (itself stacked on unqualified PR #2). Implementation cannot be merged or called validated until both predecessor gates pass.

## Goal

Agents declare an intent to change an immutable snapshot without changing authoritative state. The system records canonical proposals and revisions linking that exact proposal, snapshot and prior revision. Ancestry can be verified locally without a full repository checkout.

Non-goals: moving a protected channel, comparing/merging edits, trusted identity, authorization, rebase, signing, policy decisions, chronology and rollback. Actor names are untrusted claims.

## Typed objects

Extend SHA-256 domain-separated content identifiers:
- p1_ followed by 64 lowercase hex for proposal: SHA-256(ASCII("openscion.proposal.v1") + NUL + u64_BE(length) + payload).
- r1_ followed by 64 lowercase hex for revision: SHA-256(ASCII("openscion.revision.v1") + NUL + u64_BE(length) + payload).
Both objects have immutable content-addressed, no-overwrite storage and digest-verified reads.

Canonical proposal encoding:
- Magic 8 bytes OPROP001.
- u8 base_present: 0/1, then 32 raw bytes of a referenced r1 revision iff 1.
- raw 32-byte digest of candidate s1 snapshot.
- u16_BE actor byte length, ASCII actor claim (1..80, characters A-Z, a-z, 0-9, underscore, hyphen).
- u16_BE intent byte length, UTF-8 intent (1..2048 bytes, no NUL, no other control characters except LF or TAB, no CR).
- No timestamps, trailing data, undocumented fields or versions.
- Max payload 4096 bytes.

Canonical revision encoding:
- Magic 8 bytes OREV0001.
- u8 parent_present 0/1, then 32 raw bytes of parent r1 iff 1.
- raw 32-byte digest of candidate s1 snapshot.
- raw 32-byte digest of proposal p1.
- No trailing bytes. One parent only in v1; multi-parent merges need a future version.

## Invariants and behaviors

1. propose(base, snapshot, actor_claim, intent) requires verified referenced snapshot and, if present, verified base revision. It must never advance or create a channel head; repeated proposal is idempotent.
2. get_proposal independently validates ID/digest, canonical encoding and both referenced objects.
3. create_revision(proposal_id) derives parent and snapshot **only** from validated proposal; caller cannot override the references.
4. get_revision verifies digest and canonical encoding, its proposal ID, exact parent/snapshot equality, parent existence and candidate snapshot content.
5. ancestry(revision_id) returns [revision, parent, ... root], guards cycles and limits traversal to 4096. Missing, corrupt or inconsistent ancestor fails closed.
6. Verified snapshots themselves validate each referenced blob. Missing objects are never silently synthesized.
7. Only a later separately authorized promotion layer may change a protected channel. There is no main ref in this increment.
8. Proposals can share a base and diverge; neither becomes automatically authoritative.
9. Revision objects cannot be presented as supply-chain attestations or proof of agent identity.

## Proposed Rust API and CLI

- ObjectStore::put_proposal(&Proposal) -> ObjectId
- ObjectStore::get_proposal(&ObjectId) -> Proposal
- ObjectStore::create_revision(&ObjectId) -> ObjectId
- ObjectStore::get_revision(&ObjectId) -> Revision
- ObjectStore::ancestry(&ObjectId) -> Vec<ObjectId>
- Proposal::new(base, snapshot, actor_claim, intent), encode/decode, Revision::decode.
- openscion proposal create <repo> <root|r1_ID> <s1_ID> <actor-claim> <intent>
- openscion proposal show <repo> <p1_ID>
- openscion revision create <repo> <p1_ID>
- openscion revision show <repo> <r1_ID>
- openscion revision ancestry <repo> <r1_ID>
- JSON responses return typed IDs and sanitized fields; raw user-provided text must be safely escaped if included.

## TDD requirements

F389-01: deterministic proposal IDs; varied payloads differ.
F389-02: creating proposal does not change protected heads, tracked files or snapshots.
F389-03: root and single-parent revisions deterministic and verifiable.
F389-04: competing agents from same base coexist as immutable records.
F389-05: missing/corrupt base, proposal or snapshot denied; wrong-kind ID denied.
F389-06: oversized actor/intent, non-UTF-8, control chars, forged/truncated bytes refused.
F389-07: ancestry exact ordered chain; missing or corrupt ancestor denied.
F389-08: proposal vs revision namespaces cryptographically separated.
F389-09: CLI create/show/ancestry end-to-end with physical on-disk inspection.
F389-10: queries require no checkout, network or mutation.
F389-11: concurrency creates independent proposals without promotion.
F389-12: prior bootstrap/blob/snapshot regressions continue passing.

## Qualification and security limitations

Commit requirements and contract test cases before implementation. Run Cargo tests, fmt/clippy, manual CLI round-trips and corrupt-object negatives with raw observed output, toolchain versions, SHA and independent review; no GitHub Actions. Rust/Cargo and a Windows test environment are unavailable in this executor, so RED/GREEN runtime gates remain BLOCKED. Cryptographic integrity does not establish identity, authorization, signing, rollback or supply-chain provenance. Treat serialized inputs as untrusted and bound recursive work.