# M1 Linux process-kill durability qualification — 2026-10-17

**Disposition:** 70/70 observed Linux SIGKILL/retry checkpoints PASS; 20-way CAS and no-overwrite contention PASS. **NOT** a Windows release qualification, power-loss simulation, or independent security approval.

## Scope and source

- Initial executed PR #3 source SHA: `27f9ea3a619fc42f5c557a37aef7249c3a6a7c54` (`qa/linux/faultshim.c` + `qa/linux/crash_qualification.py` committed; no Rust source modifications since prior tested branch).
- Host: isolated disposable Vercel Linux sandbox, kernel `6.18.49`, x86_64, glibc `2.43`. The exact host filesystem was not independently qualified as ext4/XFS; these results apply only to the observed sandbox filesystem.
- Rust 1.85.1 and reviewed Cargo.lock; dynamically linked GNU target compiled with Zig 0.13.0 `zig cc` as linker.
- Binary SHA-256: `c4bc159380af7161c72d15cec9203d2c4098a3845edb7192a74434c6556d5f1c`.
- Test-only preload shim SHA-256: `8ebcc7621ab9f6cd4203d78af155d4abadba7033e1d4ad01538a97e26794e816`.
- Run interval UTC: `2026-10-17T19:24:58.548174+00:00` to `2026-10-17T19:24:59.900200+00:00`.
- No GitHub Actions or credential-bearing production fixtures.

## Observed results

| External pause / SIGKILL checkpoint | Passed / 10 | Canonical destination at pause | Orphan staging artifacts |
|---|---:|---|---:|
| Blob before stage fsync | 10/10 | Absent, retry publishes same correct digest | 10 |
| Blob after stage fsync | 10/10 | Absent, retry publishes same correct digest | 10 |
| Blob before hard-link publication | 10/10 | Absent, retry publishes same correct digest | 10 |
| Blob after hard-link publication | 10/10 | Present; retry returns same existing identity | 10 |
| Blob before parent-directory fsync | 10/10 | Present; idempotent retry returns existing identity | 0 |
| Checkout before stage-directory fsync | 10/10 | Absent; retry publishes valid checkout | 10 |
| Checkout after no-overwrite publication | 10/10 | Present; retry rejects existing destination | 0 |
| **Total** | **70/70** | **All recovered correctly** | **50** |

The 50 remaining private stage artifacts are not published objects. They **are an operational disk-usage concern**, explicitly tracked as FOSS-485; age-only garbage collection would not be safe with active writers.

Additional manual concurrency observed:
- 20 simultaneous identical blob importers: **20/20** succeeded and produced one identical `b1_` ID.
- 20 simultaneous snapshot checkout publishers to the same destination: **1** succeeded; **19** returned `E_ALREADY_EXISTS`; materialized bytes matched the verified source.
- Readbacks recomputed the domain-separated digest and checked private POSIX object permissions.
- Every paused process acknowledged the named barrier and was killed with actual `SIGKILL` before new-process recovery; this is distinct from simply testing a library mock.

## Durable evidence archive and verification

Four source-controlled text parts encode a single gzip tarball of raw stdout/stderr, barrier sentinels, built fault shim, SHA-256 manifest and JSON results (779 tar entries; fixture source data excluded from archive). Paths:

- `docs/engineering/evidence/M1-linux-crash-2026-10-17.tar.gz.b64.part00`
- `docs/engineering/evidence/M1-linux-crash-2026-10-17.tar.gz.b64.part01`
- `docs/engineering/evidence/M1-linux-crash-2026-10-17.tar.gz.b64.part02`
- `docs/engineering/evidence/M1-linux-crash-2026-10-17.tar.gz.b64.part03`

The four parts were **read back from GitHub, concatenated, decoded and extracted** independently of their original upload path; checksums matched:

- Reconstructed `tar.gz`: 31,697 bytes, SHA-256 `9e4232146b57992c4b63871f07e73a17bfd2fa18a01079a6fc0dfa620876c730`.
- Extracted `summary.json`: 128,560 bytes, SHA-256 `a6b8713c945ae884a4634d67bc18854a086b4134fe2d7d85b44956af822e449d`.

Reproduction and extraction commands are in `qa/linux/README.md`. Source-controlled checksums are evidence provenance identifiers, not independently signed attestations.

## Engineering/security review outcome

**Demonstrated:** On this Linux host, actual process death at the seven tested boundaries never produced a wrong canonical digest, unexpected checkout overwrite, or inconsistent retry result. Crash intermediates can remain private and untrusted.

**Not demonstrated:** power-loss/dirty-cache ordering, Linux ext4/XFS or network-FS specific durability, Windows NTFS/DACL/reparse handling, hostile same-UID filesystem races, independent reviewer verification, cryptographically anchored provenance, protected channel promotion, or automated safe orphan reclamation. Windows source review found Unix-gated permission validation and no equivalent protected-DACL enforcement; tracked FOSS-484.

**Merge decision:** PR #2/#3/#4 remain draft and NOT authorized for merge until Windows native execution and independent security signoff. This Linux evidence resolves the scoped SIGKILL/retry observation, not the full storage safety qualification. No modification to `main` and no GitHub CI runs.
