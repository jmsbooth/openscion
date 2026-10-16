# SDD / TDD / manual validation protocol — v0.1

## Issue template
**Requirement ID:** SPEC-XXX / REQ-NNN.
**Preconditions:** baseline commit, Rust toolchain version, execution OS and dependencies.
**Inputs/outputs:** schema, exact happy path and expected machine-readable errors.
**Security controls:** caller identity, authorization scope, data handling and audit obligations.
**Consistency:** invariants, concurrency, recovery and replay behavior.
**Acceptance:** positive, negative, regression and manual observation cases.
**Evidence:** execution log, external file/digest artifacts, result owner, review decision.

## Required sequence
1. Commit original spec and threat/acceptance cases, then open a branch.
2. Author tests that fail for the intended missing behavior (RED); preserve observable RED result.
3. Implement minimum functionality; prove passing tests (GREEN), refactor without losing coverage.
4. Run manual feature commands individually on a temporary filesystem, including `cat`/`sha256sum`/listing the objects, checking content and inspecting stable references.
5. Attempt security bypasses and tampering, stale-head races, bad paths, bad approvals and incomplete artifacts.
6. Save **raw** `cargo test`, `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo audit` (when available), `cargo deny` and explicit manual session transcripts.
7. Attach environment manifest, exact source SHA, command arguments, timestamps, expected/actual results and SHA-256 of evidence files to the PR and Linear issue; do not mark absent tools as PASS.
8. Human/independent review of test sufficiency, policy behavior and diff; merge only after locally witnessed qualification.

## Initial manual acceptance cases
| ID | Scenario | Expected |
|---|---|---|
| MAN-001 | `init` empty directory, inspect store | deterministic initialized metadata, no source rewrite |
| MAN-002 | create proposal for file A | channel `main` remains unchanged |
| MAN-003 | same source bytes, same type | stable object ID |
| MAN-004 | change stored object bytes | verification fails; fail closed |
| MAN-005 | promotion lacking trusted evidence | denied; main unchanged; denial recorded |
| MAN-006 | promotion with binding evidence and approval | exactly one new head and matching receipt |
| MAN-007 | two proposals against same old head | at most one competing promotion succeeds |
| MAN-008 | rollback B to A after B promotion | new event references B and A; B audit preserved |
| MAN-009 | restore target workspace | file bytes match snapshot hashes |
| SEC-010 | `../`, absolute, symlink, case/Unicode collision | no traversal, no overwrite or disclosure |
| SEC-011 | evidence for revision A used for B | deny |
| SEC-012 | agent approval or expired delegated credential | deny |
| REG-013 | process termination during write/promotion | no exposed partial state; recovery verified |
| REG-014 | replay previously accepted request | no duplicate promotion |

## Evidence directory format (future)
`evidence/<date>/<commit>/<case-id>/` includes `env.txt`, `commands.txt`, `stdout.log`, `stderr.log`, `expected.md`, `observed.md`, `sha256sums.txt`. Attach via PR artifacts or issue links; do not commit secret values or machine-specific credentials.

## Reproducibility and test integrity
- No paid GitHub Actions dependency. Tests execute locally on isolated runners, with transcripts saved and inspected.
- Distinguish `NOT_RUN`, `BLOCKED`, `FAIL`, and `PASS`; empty or missing evidence is never green.
- An agent cannot be the sole trust authority for evidence validating its own code.
- Gate test suite version, policy hash and exact revision subject digest; a passing result for an older revision never transfers silently.
- Redact credentials from logs; securely retain evidence with documented retention and immutable external checkpointing when available.

## Current qualification
**NOT_RUN/BLOCKED:** The working environment does not currently contain a Rust compiler or Cargo, and external package downloads are not available. Design files alone must not be described as a functional MVP.
