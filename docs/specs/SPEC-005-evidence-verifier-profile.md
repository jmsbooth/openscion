# SPEC-005 — Independent signed evidence verifier (experimental profile)

**Status:** DRAFT / TESTED IN ISOLATION / NOT PRODUCTION-APPROVED  
**Linear:** FOSS-478; successor FOSS-479; predecessor release gates FOSS-397/398/465 and FOSS-484  
**Parent contracts:** SPEC-004, ADR-0004 (both currently proposed)  
**Implementation location:** `qa/spikes/evidence-verifier/`, its own Cargo workspace (not part of `main` Rust runtime)  
**No GitHub Actions.** No client-selected trust roots, direct head writes, receipts, audit-chain mutation, authority DB access or automatic promotion in this increment.

## 1. Purpose and boundary

A parallel agent can propose immutable candidate source revisions but must not self-approve a protected channel promotion. The trusted authority must use the identity authenticated by its OS/IPC/API boundary, resolve its own channel policy, current key/trust epoch, secure clock and revocation feed, and then verify independently signed authorization scoped to the exact candidate.

`actor_claim`, a JSON field called `passed`, the hash of a revision, a local agent-generated approval, and an agent-selected public key **never** confer trust. A verified Ed25519 signature proves possession of a key only relative to an independently configured trust anchor. Actual release approval additionally requires a configured role, current policy, explicit evidence bytes and revocation freshness.

This experiment takes a `TrustView` from the *caller*. It does not authenticate that caller or load a protected trust store. In production, that structure MUST only be constructed inside a trusted authority service, never from an agent-provided request. FOSS-487 must address the local same-UID and namespace TOCTOU isolation boundary before protected promotion.

## 2. Versioned deterministic encoding

All integers use unsigned **big-endian** encoding. Identifiers are bounded canonical lowercase ASCII. No self-describing JSON, optional extensions, numeric coercion, algorithm negotiation or unknown wire fields are accepted. Never concatenate security-relevant strings without lengths.

`PromotionRequestV1` fingerprint:

```text
SHA256(
  ASCII("openscion.promotion.request.v1") || 00 ||
  u64_BE(payload_length) || payload
)
```

The payload is, in this exact order:

| Field | Encoding |
|---|---|
| Authenticated subject | `u32_BE(length)` + ASCII (1–128); derived from trusted transport |
| Channel | `u32_BE(length)` + ASCII (1–128) |
| Expected head | one byte `00` for null or `01` + length-prefixed canonical `r1_` ID |
| Candidate | length-prefixed canonical `r1_` + 64 lowercase hex bytes |
| Policy ID | length-prefixed canonical ASCII (1–128) |
| Policy digest | exact 32-byte SHA-256 |
| Policy epoch | `u64_BE` nonzero |
| Evidence bundle digest | exact 32-byte SHA-256 of the supplied raw evidence bundle |
| Idempotency key | length-prefixed canonical ASCII (16–128) |

ASCII identifiers use lowercase letters, digits and `._-`, must start and end in an alphanumeric character, and cannot contain `..`. These are logical IDs, never filesystem paths. `requested_at` and self-declared `actor_claim` are excluded. Authenticated subject and idempotency scope are included.

`PromotionAuthorizationV1` signed message:

```text
ASCII("openscion.promotion.authorization.v1") || 00 ||
u64_BE(payload_length) || canonical_payload
```

Its exact field order is:

| Field | Encoding / invariant |
|---|---|
| Audience | length-prefixed authority audience |
| Issuer key ID | length-prefixed key ID resolving **only** in trusted store |
| Issuer key version | `u64_BE`, nonzero; exact match in trusted store |
| Algorithm | byte `01` = Ed25519, anything else rejected |
| Request fingerprint | 32 bytes, independently recomputed from authenticated subject and request |
| Channel | length-prefixed canonical ASCII |
| Expected head | null or canonical r1 ID |
| Candidate | length-prefixed canonical r1 ID |
| Policy ID | length-prefixed canonical ASCII |
| Policy digest, policy epoch | 32 bytes, then `u64_BE` |
| Evidence bundle digest | 32 bytes |
| Trusted key epoch, revocation epoch | two `u64_BE`, both nonzero |
| Claimed signer role | `02` = Reviewer; Agent `01` never permits a protected approval |
| Decision | byte `01` = allow; any other value denied |
| Nonce | 32 bytes; zero nonce forbidden; checked against read-only authoritative projection |
| Issued-at, expires-at | two `u64_BE` timestamps (seconds, trusted clock comparison) |

No field can be appended or omitted. The maximum entire signed message is **4096 bytes**; the supplied evidence bundle is bounded to **1 MiB** and independently SHA-256 checked. Signature is exactly 64 bytes and verified using a server-pinned Ed25519 key; `verify_strict` rejects signature malleability. Key IDs and version numbers are not signer-chosen trust anchors.

The above binary schema is **experimental**, not a final interoperable standard. Freeze the production schema and migration rules only after FOSS-478 review and ADR acceptance.

## 3. Trust and authorization checks

For every **new** approval:

1. Validate canonical request and derive its fingerprint using the *trusted authenticated subject*, never user JSON.
2. Bound/decode the signed binary statement, reject unknown/extra fields and unsupported algorithm.
3. Resolve exactly one trusted public key by ID + exact key version; ambiguous duplicates fail closed.
4. Verify Ed25519 signature over the **entire** domain-separated wire statement.
5. Match audience, candidate, immediate expected-head reference, channel, policy ID/digest/epoch, evidence digest and request fingerprint. Supplied bundle bytes MUST hash to the signed digest.
6. Match current server-configured channel policy; require Reviewer role in both signed statement and trusted issuer registry. The signer's configured principal must differ from the authenticated agent principal.
7. Require a trusted time source; enforce issuer activation/expiration and maximum signature validity of **900 seconds**. No clock means no new authorization.
8. Require a **fresh, known** revocation snapshot; reject stale or different revocation/key epochs, unknown keys and revoked signers.
9. Reject all-zero and used issuer/nonce pairs. A successful laboratory verification does **not** consume the nonce.

The result type `VerifiedApproval` has private fields and can only be returned by the verifier. It includes the verified request fingerprint, actual authenticated subject, trusted issuer/principal, audience, evidence digest, role/epoch bindings and nonce. No external mutator grants authority.

## 4. Transactional obligation and replays

The verifier is intentionally stateless. It is **not** a promotion authority, nonce ledger or idempotency service. A later trusted FOSS-479 authority must independently validate candidate CAS ancestry and policy, then **repeat epoch, nonce and idempotency checks inside the exclusive database transaction**, updating head/receipt/sequence/nonce atomically.

SPEC-004 PROM-019: if an identical authenticated idempotency retry matches a **previously durable accepted receipt**, the authority must verify and return the same receipt even if its former signer is now revoked or expired. It **must not** re-run this new-approval verifier to create another promotion. A changed fingerprint or subject is a conflict, not a replay success. Corrupt receipts or unavailable authority cause fail-closed behavior, never unverified recovery.

No receipt hash chain, independent time source, durable nonce record or backend binding is implemented here. Database rollback resistance needs an external monotonic anchor; local SHA hashes alone cannot prove nonrepudiation.

## 5. Threat model / limitations

| Threat | Laboratory control | Outstanding work |
|---|---|---|
| Forged review signatures / algorithm confusion | Exact pinned Ed25519 key+version; strict signature validation; fixed algorithm | Independently audited identity trust anchors and production key rotation |
| Agent self-approval | Reviewer role and signer principal disjoint from trusted caller subject | Authenticated IPC/session and multi-party decision policy |
| Stale policy, key or issuer revocation | Trusted epochs, expiry and revocation snapshot freshness checked | Atomic epoch recheck within FOSS-479 and authoritative revocation feed |
| Missing/changed evidence bytes | Bounded actual bundle SHA-256 equality | Semantic evidence validation and SLSA-style attestation profiles |
| Used nonce replay | Read-only projection denies occupied issuer/nonce | Transactional nonce reservation, retention and crash recovery |
| After-commit ambiguous response | Defined recovery contract, no verifier bypass for new requests | Durable idempotency/receipt implementation (FOSS-479) |
| Compromised same-user agent | Not addressed by local verifier | FOSS-487 isolated service identity and safe handle-based filesystem access |
| Malicious local administrator or restored old DB | Not addressed | External anchoring, recovery/fencing and operational trust model |
| Multiple reviewers / cryptographic agility | One pinned reviewer and Ed25519 only | Policy-driven quorum/algorithm profile reviewed separately |

A passing test suite is **not** a security audit or authorization to merge FOSS-478 as trusted source-control runtime. FOSS-484 native Windows release qualification and an independent reviewer remain prerequisites for production integration.

## 6. Test-first traceability

- Valid independent signed reviewer approval, stable domain-separated request fingerprint.
- Wrong key, version, signature, algorithm, scope, subject, channel, head, policy, bundle digest, audience, issuer role, duplicate trust key, stale clock/epoch or revocation, self-approval, nonce replay, truncated and extended wire all deny.
- Every truncated and single-byte-mutated position in the signed golden fixture denies without panic.
- Ed25519 signature and canonical encoding are independently checked by Python `cryptography` on a deterministic **public fixture only**, not a production key.
- Exactly reproducible `Cargo.lock`, Cargo fmt/test/Clippy, manual one-case-at-a-time execution, executable stderr/stdout artifacts and checksum manifest are required before advancing the PR.

**Release gate:** Keep the implementation on an isolated, draft, non-production branch until FOSS-397/398/465/484, FOSS-487 authority isolation review, and ADR-0004 approvals permit runtime integration.
