# M1 release review — Windows DACL hardening and exact-head qualification

**Date:** 2026-10-17. **Decision:** SOURCE REPAIRED / LINUX PASS / WINDOWS-NATIVE NOT_RUN / SECURITY APPROVAL NOT_RUN. **Do not merge PR #2/#3/#4 yet.**

## Changes

FOSS-484 introduces a Windows-specific security descriptor boundary in `crates/openscion-core/src/windows_security.rs` and wires it into repository initialization/reopen (PR #2), immutable blob/shard/checkout publication and verification (PR #3), and revision storage (PR #4).

- An explicit protected discretionary access-control list (DACL) is applied **at creation**, allowing full access only to the invoking Windows process identity, local SYSTEM, and Administrators.
- Reopening a store or object checks DACL protection, owner, exact permitted allow-ACE principals and masks; extra Everyone/Auth Users access, inherited ACEs, null DACLs and ACL inspection failures are rejected without auto-repair.
- Source-controlled Windows negative tests add an Everyone:Modify ACE to a disposable initialized store and marker; `qa/windows/M1-Qualification.ps1` also covers a stored blob, junction traversal, no-overwrite and 20-way publication.
- Windows APIs use explicit Win32 foreign-function declarations. No production subprocess invokes PowerShell or icacls.
- Threat-model limit: a malicious process running as **the same operating-system user**, an administrator, a DACL race, or an attacker replacing accessible namespace components is not isolated by this ACL design. The local M1 store is not a multi-principal sandbox.

## Exact source commits and observed runtime/compiler checks

| PR | Git HEAD at manual verification | Native Linux GNU tests | Rustfmt | Windows-target compilation/Clippy |
|---|---|---:|---|---|
| #2 FOSS-387 | `a93aad6d76e9a77a0f870767234494aa4711cf85` | 21/21 PASS | PASS | PASS |
| #3 FOSS-388 | `02aeee88ed42fd33fe38889485a922bf7d9adf02` | 46/46 PASS | PASS | PASS |
| #4 FOSS-389 | `3f73ba9edb5a87550f51274fbd87200486adcab6` | 63/63 PASS | PASS | PASS |

Tests were invoked locally in an isolated Linux sandbox with Rust 1.85.1 and manually captured outputs. The Windows target was **x86_64-pc-windows-gnu**. `cargo check --all-targets` and `cargo clippy --all-targets -- -D warnings` cross-compiled the Windows code and tests; **nothing was executed on Windows**.

An attempted standalone Windows PE cross-link using Zig 0.13.0 could not find GNU Windows runtime libraries `gcc_eh`, `msvcrt` and `gcc`. This is a **host toolchain/linker qualification gap**, not evidence of an OpenScion source error or a passed Windows build. The Windows `cargo check` remains the highest verified Windows-target gate.

Earlier Linux SIGKILL/restart evidence (70/70, 20-way contention) is archived in `M1-process-kill-qualification-2026-10-17.md`; it exercises Linux process termination, **not** NTFS or electrical power loss.

## Raw inspection artifacts

The complete observed Linux test, Rustfmt, Windows cross-target compiler/Clippy outputs and machine-readable manifest are archived as base64 text at `docs/engineering/evidence/M1-acl-hardening-2026-10-17.tar.gz.b64`.

Reconstruct and independently inspect:

```sh
base64 --decode docs/engineering/evidence/M1-acl-hardening-2026-10-17.tar.gz.b64 > /tmp/M1-acl-hardening-2026-10-17.tar.gz
sha256sum /tmp/M1-acl-hardening-2026-10-17.tar.gz
# Expected: 0e1b65fb59e3cbc1de666bb48df3a85e6a34a5b72833b3f66a1c091bf76c6b22
mkdir -p /tmp/openscion-acl-evidence
tar -xzf /tmp/M1-acl-hardening-2026-10-17.tar.gz -C /tmp/openscion-acl-evidence
cat /tmp/openscion-acl-evidence/openscion-acl-qual-20261017/manifest.json
```

The base64 file was read back from GitHub, decoded, and verified against the expected archive checksum. These are raw test artifacts, **not independent cryptographic attestations**.

## Remaining release gates — no waiver

1. **FOSS-484 native Windows NTFS**: run Cargo tests, actual file creation, DACL inspections, Everyone/Authenticated Users negative injection and restoration, junction/reparse, casefold and no-overwrite race tests. Source code may need further corrections. This was not executed in the current Linux environment.
2. **Crash/power-loss durability**: run Windows process termination and supported-filesystem flush/restart tests, and Linux host fsync/power-loss qualification where required. Linux SIGKILL test does not simulate a power outage.
3. **Independent security review**: require a separate reviewer to sign off local identity model, ACL implementation and known same-user race limitations, exact dependency lockfile, publication algorithm and artifacts.
4. **Sequential integration**: after 1–3 pass, merge PR #2 to main, retarget/validate PR #3 against new main, merge PR #3, then retarget/validate PR #4. Never infer qualification from GitHub's clean mergeability.

PR #5 (architecture/specifications and isolated redb 2.6.4 evaluation) was merged separately. ADR-0004 remains PROPOSED and FOSS-479 protected promotion is not yet authorized. No GitHub Actions credits were consumed.
