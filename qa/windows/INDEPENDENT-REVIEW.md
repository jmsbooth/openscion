# FOSS-484 — Independent Windows NTFS security review record

**Status: UNEXECUTED / UNSIGNED TEMPLATE.** This document does not certify OpenScion. It must be completed by a reviewer independent of the implementation, using a native Windows host and the exact tested Git heads. Do not commit private machine paths, secrets or personal credentials.

## Scope and identity

| Item | Reviewer entry |
|---|---|
| Reviewer identity / organization / date | **NOT PROVIDED** |
| Reviewer independence (not implementer or agent owner) | **NOT VERIFIED** |
| Native Windows version/build and NTFS volume | **NOT RUN** |
| Native Rust version and linker toolchain | **NOT RUN** |
| PR #2, #3, #4 exact HEAD SHAs and workspace lock hashes | **NOT RUN** |
| Windows binary SHA-256 | **NOT RUN** |
| Evidence bundle path and SHA-256 | **NOT RUN** |
| Local test runner `summary.json` hash and raw ACL files | **NOT RUN** |

## Required manual qualification

Run `qa/windows/README.md` and `qa/windows/M1-Qualification.ps1` on a fresh, disposable NTFS fixture. The existing script is not a substitute for independent inspection.

- [ ] Native Windows Cargo workspace tests, build and executable smoke run verified
- [ ] Rustfmt and Clippy warnings-denied verified on that exact head
- [ ] Protected private DACL **at creation** for `.openscion`, marker, CAS root, shard and blob
- [ ] Owner matches intended service user; SYSTEM and Administrators are explicit; no unintended principals or inherited ACEs
- [ ] Tampered `Everyone:Modify` ACL rejected at metadata, marker, CAS root/shard and blob, with source bytes unaffected
- [ ] Unexpected ACE flags (`INHERIT_ONLY`, inheritance mutation) rejected, and ACL restoration verified
- [ ] Junction/reparse/symlink ancestor and object-path negative cases return safe refusal
- [ ] Windows casefold collisions and reserved device names blocked
- [ ] Twenty checkout contenders yield exactly one published destination, nineteen already-exists results, identical bytes
- [ ] Native Windows process-kill/restart evidence collected; staging leftovers and recovery inspected
- [ ] Power-loss durability claims bounded to an actually tested filesystem/storage device; no claims without execution
- [ ] Security principal boundary, same-SID agent risk, pathname TOCTOU limitations (FOSS-487), and external provenance limitations reviewed
- [ ] Commit SHA of remediation and all post-remediation regressions recorded
- [ ] All raw logs retained outside ephemeral runner and independently hashed

## Verification and disposition

**Reviewer disposition: NOT REVIEWED.**

Decision must be **APPROVE**, **REJECT**, or **HOLD** with explicit reasons. A failed or skipped required test cannot become approval solely because GitHub reports a clean merge. FOSS-484 requires native Windows execution and independent signoff before PRs #2–#4 are merge-authorized.

Reviewer findings:

> None recorded. Do not treat this template as a signed review.

Signoff method, reference and date:

> Not signed.

After approved evidence is attached and exact source heads requalified, merge PR #2 to `main`, reconcile/qualify PR #3, merge PR #3, then reconcile/qualify PR #4 and merge. Each post-merge check must be executed locally with GitHub Actions disabled. FOSS-478 remains blocked until these gates and the agreed authority trust boundary are resolved.
