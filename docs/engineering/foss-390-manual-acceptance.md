# FOSS-390 — Manual promotion qualification and adversarial evidence plan

**Status:** CONTRACT ONLY / NO EXECUTABLE IMPLEMENTATION.  
**Never mark a case PASS based on written expected behavior or mock data.**

The sequence starts **after** FOSS-397, FOSS-398 and FOSS-465 are independently qualified and PRs #2/#3/#4 are sequentially merged. Code must not modify an authoritative channel until real signer verification, trust anchors and transaction-bound revocation are implemented.

## Evidence header (required for every run)

| Attribute | Actual value (fill from observed run) |
|---|---|
| UTC timestamp / operator / independent reviewer | NOT_RUN |
| Git HEAD / PR exact SHA and Cargo.lock SHA256 | NOT_RUN |
| OS/kernel/filesystem/ACLs / Rust compiler/toolchain | NOT_RUN |
| redb/rusqlite selected exact version and flags | ADR not accepted |
| Trust-anchor fixture key IDs / policy epoch / issuer epoch | NOT_CONFIGURED |
| State DB path (disposable fixture only), DB checksum/hash before/after | NOT_RUN |
| Evidence-bundle digest, candidate r1 ID and expected head | NOT_RUN |
| Command, stdout, stderr, exit, duration, actual result | NOT_RUN |
| Security finding, remediation SHA and retest | NOT_RUN |

Do not store private signing keys or credentials in public logs. Generate short-lived fixture keys in a disposable isolated test environment; public key IDs, hashes, signed test attestations and redacted logs can be attached. Production keys are forbidden in test fixtures.

## Prerequisite tools — execute separately

    git rev-parse HEAD
    rustc --version
    cargo --version
    cargo metadata --locked --offline --format-version 1
    cargo tree --locked --offline
    cargo test --workspace --locked --offline -- --nocapture
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets --locked --offline -- -D warnings
    cargo build --workspace --locked --offline

If the target promotion contract and test binary do not yet exist, record NOT_IMPLEMENTED, not PASS. Generate and review Cargo.lock before attempting \`--locked --offline\`, with approved cached dependencies. No GitHub Actions.

## Manual scenario records (not executable commands until API exists)

| Case | Setup / action | Required observed storage invariant |
|---|---|---|
| PROM-001 | New channel, root revision and independent valid evidence | head=r1, sequence=1, one receipt/chain head/idempotency |
| PROM-002 | Candidate parent=current head and fresh independent evidence | sequence advances by exactly one, receipt links previous |
| PROM-003 | 20+ concurrent authenticated agents promote distinct children against same expected head | Exactly 1 success; 19+ E_HEAD_CONFLICT, exactly one receipt |
| PROM-004 | Missing/corrupt blob, snapshot, proposal, revision or ancestor | Denied; byte-identical authority DB logical state |
| PROM-005 | Impersonated actor_claim, unsigned passed=true, unknown key ID, wrong signature algorithm and wrong audience | All denied; no writes |
| PROM-006 | Key revoked, policy epoch changed, evidence expired *between* precheck and write txn | Denied at transaction-time check |
| PROM-007 | Same idempotency key+fingerprint replay; then key+different request | First returns identical existing receipt; second E_IDEMPOTENCY_CONFLICT |
| PROM-008 | Replayed approval nonce bound to different candidate/channel/head | Denied; consumed nonce cannot endorse distinct request |
| PROM-009 | Kill/terminate process at each documented fault checkpoint; restart | No torn state: either original head and no receipt, or new head with matching receipt/seq/nonce/idempotency |
| PROM-010 | Mutate receipt bytes, remove previous receipt, corrupt DB root table | Authority refuses further promotion and reports E_AUDIT_CORRUPT |
| PROM-011 | Decrease authority clock, use unknown revocation state, attack storage ACL | Denied; reason classified without path/key disclosure |
| PROM-012 | Revert to old snapshot via new revision with parent=current head | New receipt created, previous head/receipts preserved |
| PROM-013 | Native Windows NTFS with ACL, junction, crash and restart | No reparse escape, no permissive authority file access, durable transaction verified |
| PROM-014 | Native Linux ext4/XFS with inode/link and SIGKILL/restart | No partial journal/read-only bypass; owner-only data |
| PROM-015 | Start second writer process on same authority directory | Second authority is denied or safely serialized by documented single-writer lock; never split-brain |
| PROM-016 | Measure 2, 20, 100 simultaneous contenders | Report actual p50/p95/p99 latency and throughput, CPU/memory and serialized-write bottleneck |
| PROM-017 | Audit dependency graph, license, advisories, MSRV and lockfile hashes | No unresolved prohibited dependencies or unsupported Rust version |
| PROM-019 | Complete a valid promotion, let original signer authorization expire or become revoked, then retry identical subject/channel/key/request; try altered payload | Identical replay recovers *the same already committed receipt* without a write or reauthorization; altered payload is rejected; no new promotion can rely on expired/revoked evidence |

## Fault injection protocol

Implement explicit **test-only** failpoints with deterministic process barriers. Record the failpoint name and state before/after restart. At least:
1. \`FP01_after_input_validation\`
2. \`FP02_after_candidate_verified\`
3. \`FP03_after_signature_verified\`
4. \`FP04_after_write_transaction_begins\`
5. \`FP05_after_head_compare\`
6. \`FP06_after_receipt_insert\`
7. \`FP07_after_head_update_before_commit\`
8. \`FP08_immediately_before_commit\`
9. \`FP09_after_commit_before_receipt_response\`

For every failpoint, repeat **at least** 10 times on Linux and Windows, use a disposable database, inspect channel/receipt/idempotency/nonce *from a new process*, compare independent SHA-256 receipt computation, and never treat \`kill\` exit code as a successful transaction test. Unavailable platforms are NOT_RUN. A mock transaction backend cannot qualify the redb crash boundary.

## Attestation and verifier review

- Identity of approver is verified from trusted key, not from serialized actor label; check issuer authorization for channel/scope.
- The exact trusted verifier algorithm/profile, key rotation and revocation source must be approved before implementation.
- Evidence covers request fingerprint, channel, expected head, candidate, policy digest+epoch and validity window.
- Confirm untrusted evidence cannot choose the policy, downgrade algorithm, rewrite expiration, or sidestep reviewer separation requirements.
- Confirm stale revocation feeds fail closed. Verify receipt hash chain with a separate implementation; distinguish local hash integrity from externally anchored nonrepudiation.

## Merge decision gate

To mark FOSS-390 Ready for Review, attach:
- Spec and ADR approval; versioned crypto verifier profile;
- Test sources committed before implementation and **observed** RED/GREEN logs;
- Real workstation Cargo build, test, fmt, clippy + SBOM/license/advisory outputs;
- Linux/Windows race/ACL/crash/recovery raw logs and independently computed receipt IDs;
- Independent security reviewer signature, remediation list and release decision.

**Do not claim FOSS-390 success now.** All cases are NOT_RUN; no application implementation exists on this branch.
