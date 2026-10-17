# SPEC-004 — Gate-bound atomic promotion and durable provenance

**Issue:** FOSS-390  
**Status:** PROPOSED / NOT IMPLEMENTED / RELEASE BLOCKED  
**Scope:** Single-node, single-authority protected-channel promotion, redb candidate gated by ADR-0004.  
**Dependencies:** FOSS-387/388/389 merged only after their manual acceptance and independent security review.  
**Method:** SDD first; contract/negative tests authored before implementation; observe RED then GREEN, inspect actual persistence, no GitHub Actions credits.

## 1. Security objective

Make an immutable candidate revision authoritative **only after** a trusted verifier evaluates external policy/evidence and authenticates an independent approval. If multiple agents race, one valid request can win for a given expected head; all others fail closed without rewriting history. The authoritative channel head, monotonic sequence, immutable receipt and idempotency record must be committed atomically.

OpenScion \`actor_claim\` in a p1 proposal is **not an authenticated principal**. An r1 revision's digest proves bytes match a particular ID, **not** that an actor was trustworthy, reviews occurred, code is safe, or the revision is approved.

## 2. Trust boundaries and prerequisites

- **Untrusted:** agents, workspaces, requested target revision, proposed actor name, submitted receipt/evidence bytes, claimed policy pass flags, arbitrary filesystem paths, and CLI arguments.
- **Trusted boundary:** dedicated authority process and authenticated caller transport; tightly controlled trust-anchor store, revocation and policy versions; local transactional promotion database; monotonic channel sequences.
- **Independent gate:** signatures are verified over a canonical, versioned statement bound to the exact channel, candidate revision, expected head, policy digest, evidence digest, decision, issuer role, issued/expiry, approval purpose and unique nonce. A string saying \`passed=true\` is never sufficient.
- **CAS storage:** candidate r1 revision and all referenced proposal/snapshot/blob ancestors must be durably present and digest-verified **before** making a head authoritative. Current M1 filesystem race controls are not sufficient against hostile same-user writers; the authority must own isolated, protected object storage.
- **Single-node only:** no NFS-based distributed authority, implicit leader election, multi-region failover, federated identities, decentralized consensus or arbitrary rebase in this increment.
- **Cryptographic algorithms:** allowlisted at server configuration; signer key material cannot come from user request fields. Specify algorithm identifiers and trust-root rotation in a separate reviewed crypto profile before implementation.

## 3. Wire contract — request

\`PromotionRequestV1\` (canonical byte serialization; version 1; field order and limits frozen before implementation):

| Field | Type / bound | Requirement |
|---|---|---|
| protocol | fixed \`openscion.promotion.request.v1\` | Domain/version separation |
| channel | canonical ASCII identifier, 1..128 bytes | Trusted channel policy resolves it; not caller-selected filesystem path |
| expected_head | r1 ID or null | Null permitted only for creation of an unborn channel |
| candidate | r1 ID | Digest-verified existing revision and full ancestry |
| policy_id / policy_digest / policy_epoch | pinned IDs + u64 | Approved policy, not client-selected policy |
| evidence_bundle_digest | 32-byte cryptographic digest | Bind full external gate evidence bundle and signer identities |
| authenticated_subject | derived from authority's authenticated session | Must NOT be trusted from request JSON |
| idempotency_key | 16..128 canonical bytes | Scoped to subject + channel; collision is an explicit error |
| requested_at | optional informational time | Never used in place of authority clock |

A \`PromotionAuthorizationV1\` verified by an independent evidence authority binds request fingerprint, channel, candidate, expected_head, policy, evidence, signer role, decision=allow, nonce, validity interval and revocation epoch. The authority does **not** accept \`actor_claim\` or \`verification_passed\` from the agent as credentials. Reject unsupported signature algorithms, untrusted key IDs, wrong audience, key rotation ambiguity, revoked/expired evidence, stale policy epoch and duplicated approval nonces.

The canonical request fingerprint is SHA-256 of a domain-separated, length-prefixed, versioned canonical encoding of all security-relevant request fields **excluding** the untrusted requested_at. Unknown/duplicate fields and noncanonical byte encodings fail. ID references use typed binary digest + kind, never string concatenation without unambiguous framing.

## 4. Authority-state schema (conceptual)

All rows/tables are in **one transactional authority database**; schema is logical, not a redb API commitment.

- \`channels[channel]\`: head (r1|null), sequence (u64), last_receipt_id, policy_id, policy_digest, policy_epoch, authority_epoch.
- \`receipts[(channel,sequence)]\`: canonical \`PromotionReceiptV1\` bytes + SHA-256 receipt digest, bound previous receipt ID and request fingerprint.
- \`idempotency[(authenticated_subject,channel,key)]\`: request fingerprint, receipt ID, decision, sequence.
- \`used_nonces[(trusted_issuer,nonce)]\`: request fingerprint + receipt ID, within authority's configured replay-retention.
- \`policy_epoch[policy_id]\` and \`issuer_epoch[issuer]\`: locally authoritative allowed epochs / revocation state; updates synchronized with promotion transactions.

All reader-visible records must cross-reference consistently. An accepted promotion is never represented solely by an object written to a separate logfile.

\`PromotionReceiptV1\` binds protocol/version, authority identifier+epoch, channel, previous head, new head, expected head, sequence, previous receipt digest, approved candidate and full request fingerprint, policy digest+epoch, evidence bundle digest, authenticated subject, authorized approver identifiers+key versions, accepted decision and trusted authority timestamp. \`receipt_id = SHA256("openscion.promotion.receipt.v1" || 0x00 || u64_BE(encoded_len) || canonical_receipt)\`. The predecessor receipt digest is the cryptographic **application** chain, independent of the database's internal checksums. A hash chain is tamper-evident only relative to a protected root/anchor; an attacker with write access to all historical records can recompute it, so future anchoring/signatures are required for external nonrepudiation.

## 5. State machine

| From | Input | Guard | Transition |
|---|---|---|---|
| Unborn | initial candidate | expected_head=null, verified *root* r1, valid authority gate | (candidate, seq=1, receipt) |
| Active(head=H, seq=n) | candidate C | expected_head=H; C.parent=H; verified bound policy+evidence, n not overflowed | (head=C, seq=n+1, receipt) |
| Active | identical accepted idempotency retry | authenticated subject/key/fingerprint exactly match prior | Return same verified receipt, **no new transaction effect** |
| Any | stale head / unauthorized or malformed request | any guard fails | Unchanged head, seq, receipts, idempotency; typed denial |
| Any | restart | durable database opens and invariant verifier passes | Resume only from valid head+receipt+sequence |
| Any | corruption / conflicting issuer state / ambiguous recovery | any invariant fails | **STOP**, do not auto-repair, promote or fork authority |

M1 deliberately forbids:
- ancestry skipping, parent rebinding, force-push, multiple parents, rewritten history or implicit merges;
- moving a protected head directly backward as "rollback"; **revert** must be a new candidate whose parent is the current head and whose content restores an earlier snapshot, subject to new policy authorization;
- head movement from an agent's local branch/proposal that lacks independent gate evidence.

## 6. Transaction ordering and linearization

1. Authenticate caller; parse/bound/canonicalize input, derive request fingerprint.
2. **Read-only retry recovery**: look up idempotency under (authenticated subject, channel, key). If the stored fingerprint matches, independently verify the committed receipt and return it with \`OK_IDEMPOTENT\`; no new authorization or promotion occurs. An identical retry remains recoverable after the original authorization expires or is revoked. If the fingerprint differs, fail \`E_IDEMPOTENCY_CONFLICT\`. Malformed/audit-corrupt state must fail closed. This step does **not** skip caller authentication.
3. For a previously unseen key, independently verify candidate r1, proposal, full ancestor chain, snapshot and all referenced blobs in authority-controlled immutable storage.
4. Obtain a verified externally signed evidence decision from **trusted** verifier/trust roots; validate its binding and current time with revocation data. This stage must not modify the authoritative channel.
5. Begin the exclusive write transaction. Read channel state, policy epoch, issuer revocations, idempotency record and nonce table from the authoritative transaction snapshot. **Repeat idempotency resolution inside the transaction** to close races with another successfully committing writer; return a matching prior receipt without a new state transition.
6. Check the server-assigned channel policy/trust epoch against the signed evidence and compare \`expected_head\` to current head. Require the candidate's immediate parent equals current head (or parent=null for channel genesis) and verify no sequence overflow.
7. Atomically insert canonical promotion receipt, update channel head/sequence/last_receipt, write idempotency binding and consume issuer nonce in the **same transaction**. No external file write between these steps.
8. Commit with immediate/durable semantics. The API MUST NOT report success until durable commit returns OK and the receipt can be read back and verified. If the commit result is ambiguous (I/O failure or process loss), the caller retries with identical idempotency key and the system resolves against durable state.
9. If any check/write/commit fails, transaction aborts; head, sequence, receipt and idempotency remain consistent. An already-committed promotion is not rolled back merely because response delivery failed.

**Non-atomic external state caveat:** CAS contents or external revocation feeds can change independently of the authority database. For promotion safety, the service must own CAS and use pinned verified objects; locally authoritative policy/key-revocation versions must be checked *inside* the transaction. If the trust feed is stale, fail closed. A future replication system will need consensus over these epochs.

## 7. Typed outcomes

- \`OK_PROMOTED\`: durable head advanced and receipt verified.
- \`OK_IDEMPOTENT\`: identical prior receipt replayed with no new write.
- \`E_AUTHN\`, \`E_AUTHZ\`, \`E_EVIDENCE_INVALID\`, \`E_EVIDENCE_EXPIRED\`, \`E_POLICY_STALE\`, \`E_KEY_REVOKED\`.
- \`E_HEAD_CONFLICT\`, \`E_PARENT_MISMATCH\`, \`E_IDEMPOTENCY_CONFLICT\`, \`E_NONCE_REPLAY\`.
- \`E_CANDIDATE_CORRUPT\`, \`E_OBJECT_MISSING\`, \`E_AUDIT_CORRUPT\`, \`E_AUTHORITY_UNAVAILABLE\`, \`E_CAPACITY\`.

Machine-readable denied responses disclose only stable codes, not signer secrets, filesystem locations, key material, policy internals or evidence payload. Failures must be distinguishable from an ambiguous after-commit transport failure.

## 8. Acceptance tests / traceability

| ID | Required test (not a paper assertion) |
|---|---|
| PROM-001 | Genesis promotion uses expected_head=null and root revision; verifies seq=1 and matching receipt |
| PROM-002 | Next promotion succeeds only if immediate parent equals expected current head |
| PROM-003 | Concurrent verified contenders with same expected head: **at most one winner**, one durable receipt |
| PROM-004 | Stale head, ancestry skip, wrong parent, wrong kind and missing/corrupt CAS refs: no mutation |
| PROM-005 | Agent-authored \`passed=true\`, claimed actor ID, forged issuer, algorithm confusion, wrong audience: denied |
| PROM-006 | Expired/revoked evidence, policy/key epoch rotation, unknown revocation state: denied even if previous checks passed |
| PROM-007 | Identical idempotency retry returns exact receipt and sequence; changed payload with same key: denied |
| PROM-008 | Approval nonce replay with altered scope/candidate/channel: denied |
| PROM-009 | Crash before write txn, inside txn, immediately before durable commit, after commit/before response: restart yields either no promotion or exactly one complete promotion and valid receipt |
| PROM-010 | Receipt link and authority sequence independently recomputed; missing/altered entry prevents new promotions |
| PROM-011 | DB corruption, truncated/writable metadata, cross-user ACL or unsafe filesystem: fail closed, no auto repair |
| PROM-012 | Revert uses a **new** revision; old receipt/head history remains intact |
| PROM-013 | Cross-platform test: Linux ext4/XFS + Windows NTFS with native ACL, file locking, fsync/crash behavior |
| PROM-014 | Throughput and tail latency of 2, 20 and 100 competing agents measured, not guessed; one writer is a documented limit |
| PROM-015 | Toolchain compatibility of pinned backend, exact lockfile hashes, SBOM, advisory/license report and MSRV verified on developer hosts |
| PROM-016 | Full prior FOSS-387/388/389 regression suite passes locally without GitHub CI |
| PROM-017 | Attempt to run two authorities on one DB path results in exclusive-authority enforcement; no split brain |
| PROM-018 | Signed receipt or external anchor limitations documented and explicitly tested against forged/recomputed local logs |
| PROM-019 | Identical accepted retry after signer expiry/revocation returns prior verified receipt with no write; different fingerprint/subject fails, no new acceptance |

## 9. Local execution / evidence requirements

Do not begin trusted promotion code without a reviewed ADR and a real independently verified evidence-verifier boundary. Commit implementation-independent contract tests before implementation; observe actual RED failures and GREEN after fixes. Run individually:
- \`cargo test -p openscion-core --test promotion_contract --locked --offline -- --nocapture\` once that test target exists;
- full \`cargo test --workspace --locked --offline -- --nocapture\`;
- \`cargo fmt --all -- --check\`;
- \`cargo clippy --workspace --all-targets --locked --offline -- -D warnings\`;
- release build plus manual CLI/race/corruption/fault-injection cases on Linux and Windows.

Capture exact branch SHA, OS/toolchain/dependency versions, raw stdout/stderr/exit status, object digests, DB state (head, sequence, receipt, idempotency), fault point, independent verification and review disposition. Github Actions must not consume credits. No "test passed" string or source-only inspection substitutes for executable evidence.

## 10. Explicit limitations

No verified production authority exists yet. redb 2.6.4 is a provisional MSRV-compatible candidate, not a security approval. M1 stays single-node: no authenticated decentralization, multi-master leader election, distributed consensus or globally durable receipts. Threats from OS administrators, malicious same-UID filesystem writers, DB rollback to older backups and unavailable remote revocation feeds require explicitly defined operator trust boundaries, external anchoring and future mechanisms.

**Gate:** FOSS-390 implementation and merger are blocked by FOSS-397, FOSS-398 and FOSS-465, plus ADR acceptance and evidence-authority security review.
