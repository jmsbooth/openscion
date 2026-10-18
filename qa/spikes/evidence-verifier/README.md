# FOSS-478 — Independent evidence verifier laboratory

**Status:** SDD/TDD prototype only; non-production, no protected-channel writes, no head advancement and no configured authority. The parent \`main\` branch still contains specifications rather than the unmerged PR #2–#4 source-control runtime.

This independent nested Cargo workspace exists so signed-evidence checks can be qualified without bypassing FOSS-484 Windows/NTFS and security-review prerequisites. Its wire format is provisional (SPEC-005); no consumer should depend on it as a published public API.

## Security profile

- Rust 1.85.1; \`ed25519-dalek = "=2.2.0"\`; \`sha2 = "=0.10.9"\`. SHA-256 binds canonical request fields, policy and actual evidence-bundle bytes; Ed25519 strictly verifies a trusted reviewer signature.
- The trust roots, authenticated actor identity, policy epoch and revocation snapshot **must come from a trusted service**, never a user-submitted object. This prototype receives them through a \`TrustView\`, not an authenticated transport.
- No private production keys are shipped. Example and tests use a publicly known, deterministic seed that **must never** be reused for an actual protected channel.
- Nonce checks are read-only; they are *not* an atomic ledger. FOSS-479 must atomically recheck and reserve nonces and policy epochs, committing receipt/head/sequence/idempotency together.
- Existing committed idempotent retries after reviewer revocation must be handled by the future receipt-backed authority, not used to authorize new promotions. No durable receipt store is included.

## Manual qualification — inspect each action

Work inside \`qa/spikes/evidence-verifier\` on a provisioned workstation. Do not run GitHub Actions. Preserve exact HEAD, toolchain versions, raw outputs and exit statuses.

\`\`\`sh
git rev-parse HEAD
rustc --version
cargo --version
cargo fetch --locked
cargo metadata --locked --offline --format-version 1 > /tmp/foss478-cargo-metadata.json
cargo tree --locked --offline
cargo fmt --all -- --check
cargo test --locked --offline --all-targets -- --nocapture
cargo clippy --locked --offline --all-targets -- -D warnings
cargo build --locked --offline

# Execute individual red/green security contracts and inspect the console:
cargo test --locked --offline --test evidence_contract \
  valid_independent_signed_review_is_verified -- --exact --nocapture
cargo test --locked --offline --test evidence_contract \
  rejects_modified_signature -- --exact --nocapture
cargo test --locked --offline --test evidence_contract \
  rejects_self_approval_using_trusted_issuer_identity -- --exact --nocapture
cargo test --locked --offline --test evidence_contract \
  rejects_nonce_replay_without_state_mutation -- --exact --nocapture
cargo test --locked --offline --test evidence_contract \
  all_truncations_of_signed_canonical_wire_fail_without_panicking -- --exact --nocapture
\`\`\`

If the host has no native \`cc\` linker, separately configure an approved local linker (e.g. a provisioned Zig GNU linker) and record it in evidence. A missing linker is **NOT_RUN**, not a passed test. The crate is isolated with its own \`[workspace]\` and lockfile; it does not modify the parent runtime or the main Cargo.lock.

## Cross-implementation golden vector

\`\`\`sh
cargo run --locked --offline --example export_public_test_vector > /tmp/authorization-v1.json
cmp /tmp/authorization-v1.json vectors/authorization-v1.json

# Requires Python with cryptography's Ed25519 verifier installed:
python3 qa/independent_verify_vectors.py --vector vectors/authorization-v1.json
\`\`\`

The Python oracle independently recomputes domain-separated, length-prefixed request hashing and strictly decodes the Ed25519-signed authorization. It verifies signed bytes using a different cryptographic implementation, then checks that mutated bytes/signatures are rejected. Python packages/versions must be recorded by the reviewer; this script never installs a package or substitutes one silently.

\`vectors/authorization-v1.json\` contains **only publicly reproducible test material**. A signature check against a test public key does not validate trusted-root enrollment, reviewer independence, third-party attestation, SLSA provenance or policy semantics.

## What is NOT qualified

Native Windows NTFS/DACL tests, issuer enrollment/revocation feed source authenticity, ACL isolation between untrusted agents and the authority, server-signed receipts, key-management lifecycle, transactional replay safety, atomic promotion, recovery after actual power loss, or a third-party security assessment.

No FOSS-478 production API may be wired into promotion until FOSS-397/398/465/FOSS-484 are qualified/merged in order and the evidence-authority review approves SPEC-005 and ADR-0004. The current PR must remain a **draft evaluation**.

For the exact encoding and typed acceptance conditions see \`docs/specs/SPEC-005-evidence-verifier-profile.md\`. Raw RED/GREEN logs and exact HEAD hashes are stored separately under \`docs/engineering/evidence/\`.
