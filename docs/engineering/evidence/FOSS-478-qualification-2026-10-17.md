# FOSS-478 — Independent signed evidence-verifier laboratory qualification

**Date:** 2026-10-17 (America/New_York; executor logs UTC)  
**Scope:** Isolated, non-production SDD/TDD experiment on branch `test/foss-478-independent-evidence-verifier`  
**Tested Rust source HEAD:** `cdbc7faef120028ec0053944eb1df9988ff121f2`  
**Disposition:** LOCAL GNULINUX CRYPTO CONTRACT PASS / CROSS-LANGUAGE VECTOR PASS / WINDOWS CROSS-CHECK PASS / NATIVE WINDOWS NOT_RUN / PRODUCTION GATE NOT APPROVED.

## TDD observation

1. An intentionally reject-all verifier stub was committed with **25** contract tests. Executing the test target in a provisioned Rust 1.85.1 GNU Linux sandbox returned **24 failed, 1 passed**. The one passing case tested deterministic request fingerprinting independent of the not-yet-implemented verifier. Failure output showed `NotImplemented` for positive and security-negative acceptance cases. This is observed RED, not a compiler/toolchain failure.
2. Implemented fixed-domain canonical request/auth wire encoding, strict Ed25519 verification against caller-supplied *trusted* key registry, matching expected head/candidate/channel/evidence/policy/audience/fingerprint, authenticated-subject separation from reviewer principal, bounded evidence bytes, trusted time and epoch/revocation checks, nonce replay rejection.
3. After refining intentionally overlapping validity fixtures (revocation freshness expired earlier than the signature), **25/25** passed. Added explicit evidence-bundle hash/missingness, case/canonical identifier, trust-root uniqueness, all-zero nonce, public vector and all-offset truncation/mutation tests. **35/35** cases passed.
4. Two independent implementations checked one *public deterministic test fixture*: Rust `ed25519-dalek` created signed canonical bytes and Python `cryptography 46.0.7` recomputed the separate request fingerprint and wire decoder, verified Ed25519 and rejected forged bytes/signatures. **7/7** independent oracle cases passed. This proves the two implementations agree on the fixture; not a qualified production trust root.
5. At the exact Rust source HEAD above, a manual supervisor executed **45 separate tool/test commands**: 35 contract cases individually with `--exact`, full Cargo workspace target, Rustfmt, Clippy warnings-denied, build, dependency inspection, golden fixture export, Python oracle, Python static compilation, Rust and Cargo versions. All **45/45** returned the expected code; every individual test stdout contained precisely one passing case.

### Reproducible environment

- Rust/Cargo **1.85.1**; isolated GNU/Linux x86_64 sandbox, Zig 0.13.0 used as `cc` wrapper for build scripts.
- Isolated `[workspace]` under `qa/spikes/evidence-verifier/` (not parent OpenScion runtime), `publish=false`.
- Exact dependencies `ed25519-dalek=2.2.0`, `sha2=0.10.9` plus **36** pinned crates.io registry packages in standalone Cargo.lock (SHA-256 `b8a05913de8df2a788723f31415528f30bdae240f6a08aac216e19f08ae4a430`).
- Point-in-time OSV QueryBatch checked all 36 registry dependencies and returned **zero reported advisories**, not ongoing CVE/maintenance/security certification. Cargo metadata license inventory captured in raw archive.
- Cross-target `x86_64-pc-windows-gnu`: standalone Rust crate Cargo check and Clippy `-D warnings` both PASS (logs SHA-256 `f445b62910d1569f5cb577e759d84d358202c297e3d18137e0df665318779e4c` and `77b0cac90610b461f02914af72d8e3ba01616b628aa37f6f5f4385ddfabbd767`). **No native Windows Rust test or NTFS ACL test executed**.

## Raw evidence and GitHub round-trip verification

The archive is committed as two consecutive base64 text parts:

- `docs/engineering/evidence/FOSS-478-manual-2026-10-17.tar.gz.b64.part00`
- `docs/engineering/evidence/FOSS-478-manual-2026-10-17.tar.gz.b64.part01`

They are consecutive text parts of ONE gzip tarball, not separate compressed archives. GitHub readback → concat → base64-decode → tar extraction succeeded. Verified:
- Reconstructed gzip SHA-256: `05b6b08593bc55e8579e1ee7166c70d459c28957688e94dfd84f302fd85a42bc`
- Extracted `manifest.json` SHA-256: `64115a826dc68ff353b0ffdace248485d3c96d66e5e408deabb450f6b0357876`
- Contents: **90** stdout/stderr transcripts, 45-result manifest, original RED output, Rust golden vector, standalone lockfile, dependency/OSV and license inventories, previous Python independent oracle output.

```sh
cat docs/engineering/evidence/FOSS-478-manual-2026-10-17.tar.gz.b64.part0* \
  | base64 --decode > /tmp/FOSS-478-manual-2026-10-17.tar.gz
sha256sum /tmp/FOSS-478-manual-2026-10-17.tar.gz
mkdir -p /tmp/foss478-evidence
tar -xzf /tmp/FOSS-478-manual-2026-10-17.tar.gz -C /tmp/foss478-evidence
cat /tmp/foss478-evidence/foss478-manual-20261017/manifest.json
```

The preserved files are **unsigned manual diagnostic evidence**, not an independently anchored attestation or outside human signoff.

## Security limitations and release decision

- The verifier is stateless. A used-nonce projection supplied by a trusted caller is inspected, **not transactionally reserved**. Epochs are not rechecked under the promotion DB lock. The future FOSS-479 authority MUST do both and atomically store idempotency/head/sequence/receipt.
- No trusted clock, protected key registry, identity-authenticated IPC, reviewer enrollment, semantic attestation validation, signed receipt chain, external anchor, production revocation feed, independent human security audit or OS-principal isolation has been deployed.
- The Rust fixture signer uses a **public, deterministic test seed** and is never eligible as a production issuer. Production signing secrets and live identities are not in the repository.
- The Windows cross-target compiler run cannot substitute for native FOSS-484 NTFS/DACL and crash/durability qualification; predecessor PRs #2–#4 are still unmerged.
- SPEC-004 and ADR-0004 are proposed; SPEC-005 is deliberately DRAFT. Reproducible tests **do not** approve FOSS-478 integration, accept ADR-0004, or unblock FOSS-479.

**Decision:** keep PR #6 **DRAFT**, isolated from `main` until predecessor qualification and independent security review authorize production integration. No GitHub Actions credits consumed.
