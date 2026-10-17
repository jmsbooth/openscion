# FOSS-387 — Increment 1 validation record, 2026-10-16

## Provenance / traceability

- Approved architecture baseline on main: merged PR #1, f19069a7d2cb731087506729c97165d33ebad838.
- Feature branch: feat/foss-387-rust-cli-foundation.
- Requirement-first specification: ac2498816fc3c67256cecbce20c8e728a18cf30d.
- Test-source-first commits: f4555c4f0470a62662a72d76db7368fbe758d1ef and 63552b140af93501105f779a57cef55bfbf92628.
- Initial core implementation: 3c7172d30f5fdd29e1f7be77367c9b020b548e30.
- Initial CLI implementation: f027757177a248189e8e1f61fd27fcc5c7f5931b.
- Subsequent security hardening and adversarial test additions: Windows reparse/junction and drive-relative path handling, non-UTF8 arguments, owner-only metadata permissions.
- Source snapshot inspected after those changes: 8a7501b4bec20e73ac724189d07f859976d4f0b6 (not necessarily final PR head).

## Methods and observed evidence

**A. GitHub connector read-back (STATIC):** fetched all twelve expected implementation, test and documentation files by feature branch. Checked 14 assertions covering workspace structure, absence of third-party dependencies, marker bytes, exclusive creation, bounded read, fsync/rename calls, link/reparse defense, lexical traversal refusal, typed error strings, supported CLI operations, JSON result handling, security cases, QA guide and accurate README scope. **14/14 passed as source-level assertions**, not as compiled/functional tests.

**B. Test sources (NOT_EXECUTED):** twelve integration test functions authored for openscion-core and seven for openscion-cli (19 total); OS-gated tests cannot be counted as executed. The spec and initial test-source commits precede implementation commits. Because Rust is absent, there is no observed RED failure or GREEN success. Do not describe this as completed TDD qualification.

**C. Manual toolchain probe (BLOCKED):** recorded on 2026-10-16 at 14:47:34 UTC on Linux 6.18.44 x86_64 with git 2.47.3. rustc, cargo, cargo test, cargo fmt and cargo clippy all returned command-not-found (127). Their failures occurred before source execution, regardless of working directory. See the attached **raw** transcript:
evidence/FOSS-387/2026-10-16-toolchain-probe.txt

The raw transcript SHA-256 from the execution container:
63658bee024b3f11af43c37392ef4de4bc9eb51d8afc9f7d9344ca4ad4688dfd

## Gate status

| Gate | Outcome |
|---|---|
| Original requirements recorded before implementation | COMPLETE |
| Tests authored before implementation | COMPLETE (source only) |
| Source-level structure/security review | STATIC_PASS (14/14 assertions) |
| Cargo compilation | BLOCKED — Cargo/rustc absent |
| RED/GREEN execution | BLOCKED — Cargo/rustc absent |
| Rust unit/integration regression tests | BLOCKED — 19 tests authored; 0 executed |
| cargo fmt / clippy | BLOCKED — Cargo absent |
| Manual CLI init/status and negative security behaviors | BLOCKED — no executable |
| Windows junction/ACL/platform checks | NOT_RUN |
| Interrupted initialization fault injection | NOT_RUN |
| Cargo.lock regeneration and review | BLOCKED — Cargo absent |
| Independent security review | PENDING |
| GitHub Actions | NOT_USED (user constraint) |

## Known limitations

- This first increment intentionally does not provide source-control revisions or any cryptographic content/provenance model.
- The local filesystem checks inspect names before use. A hostile local principal with concurrent write permissions can race path replacement; this is not proven race-free, and the service architecture must use handle-relative, authenticated operations.
- Windows reparse-point checks are present in source but have not been validated on Windows.
- After a crash, an incomplete metadata directory must fail inspection; actual process-kill/fault-injection evidence is outstanding.
- The GitHub repository's *description metadata* still uses older clone wording and requires an authorized repo-settings edit; the README has been corrected.

**Decision:** retain the implementation PR as DRAFT and issue FOSS-387 IN PROGRESS pending independent local execution and review. No pass is claimed for Rust runtime behavior.
