# Independent-development protocol — draft 0.1

## Purpose and limitations
OpenScion shall be an independently authored system solving agentic change-management problems. Public architecture ideas, research papers, standards and feature descriptions may inform requirements, but source-code expressions, proprietary documentation, nonpublic designs, UI assets or verbatim protocol schemas must not be copied. **Reading Anthropic's article and implementing concepts is not a formal two-team clean room; counsel must evaluate potential copyright, patent, trademark, trade-secret and contractual concerns.** No guarantees of non-infringement are asserted.

## Research/source register (2026-10-16)
| Input | Role | Permitted use |
|---|---|---|
| Anthropic, “Redesigning source control at Anthropic,” Oct 13 (updated Oct 15), https://www.anthropic.com/engineering/redesigning-source-control | Public discussion of scale, server/client asymmetry, immutable data, sparse workspaces | Background to identify broad problems/constraints; do not reconstruct internals or reuse material |
| Git documentation / open standards | Compatibility context | Document interfaces as necessary; review code licenses separately |
| Jujutsu / Sapling / Mononoke public projects | Prior-art comparison | Compare *features* only; do not copy implementation without license and independent-design decision |
| in-toto and SLSA published specifications | Supply-chain evidence terminology | Evaluate compatibility and provenance semantics; do not claim certification |
| NIST SP 800-218 SSDF | Secure software process | Derive review/testing practices with references |

## Contributor safeguards
1. Record source-of-requirement and design rationale in an original spec before coding.
2. Do not access Anthropic internal source, leaked code, unpublished design docs, reverse-engineered endpoints or credentials.
3. Any third-party code requires explicit license compatibility and notices; avoid ambiguous snippets generated from copyrighted examples.
4. Record author, commit, signed-off design review, dependency SBOM and generated-code review.
5. Maintain a public provenance register of external standards cited; distinguishing the research source from software-code origins is mandatory.
6. Counsel reviews naming, trademarks, patent exposure and use of article concepts before public release.
7. Review README/marketing language; avoid “clone,” “official,” “compatible with Scion,” or endorsement claims.

## Design team / implementation team option
For stricter clean-room assurance, appoint distinct specification and implementation reviewers with nonoverlapping access to source materials, a written behavior-only specification, a communication log, and independent IP review. Work conducted in this conversation is **not** represented as satisfying that separation.

## Checkpoint
No software release is represented as legally cleared until a qualified reviewer records an explicit decision and scope.
