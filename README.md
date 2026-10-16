# OpenScion

**Independent, agent-native source control and change governance.** OpenScion is an experimental Rust-oriented open-source project. It is **not** a clone or implementation of Anthropic Scion, and it is not yet a functioning source-control system.

## Why
Agentic development needs a change lifecycle beyond human-paced version control: immutable candidate revisions, parallel proposals, deterministic integrity, independent acceptance evidence, narrowly delegated authorities, atomic promotion and an auditable rollback path.

## Status
**M0: specification and architecture draft only.** No compiled Rust executable or security qualification is available yet. See [roadmap](docs/roadmap.md), [architecture](docs/architecture/v0.1.md), [independent-development protocol](docs/governance/independent-development.md), and [SDD/TDD manual qualification](docs/engineering/sdd-tdd-manual-validation.md).

## Principles
- Independently designed from publicly observable industry needs; no Anthropic source code, private documentation or unpublished protocol details.
- Proposals are immutable, stable channels advance only through an expected-head atomic authorization operation.
- Cryptographic object integrity is distinct from agent identity, code review, trusted build evidence and release authorization.
- Rollback is a new forward-moving, verified promotion and never deletes evidence.
- Test-first development with manually inspected logs and archived artifacts, not GitHub Actions.
- Start with a local Rust vertical slice; distribute only after correctness, security and recovery are demonstrated.

## License
MIT. Consult [LICENSE](LICENSE). Third-party contributions and dependencies require separate license provenance checks.

## Research disclosure
The public Anthropic source-control article is a **background input identifying industry problems**, not an implementation specification. Independent design, authorship, and possible patent/trademark concerns must be reviewed before release.
