# SPEC-002A — Typed immutable blobs and canonical snapshots

**Work item:** FOSS-388. **Stage:** M1 increment 2. **Parent:** FOSS-387 / PR #2 (draft). **Status:** test-first implementation draft, NOT QUALIFIED.

## Scope

Local immutable content-addressed blobs and canonical path-to-blob snapshots. Retrieval MUST verify the digest; materialization creates a fresh directory with no destructive overwrite. Revisions, commits, mutable heads, policy-gated promotion, agent identity, GC, distribution, merge and rollback are explicitly excluded.

## Cryptographic identity (original v1 protocol)

- Use maintained RustCrypto SHA-256 via sha2 exactly 0.10.9 (dual MIT/Apache-2.0), not bespoke cryptography.
- Blob digest = SHA-256(ASCII("openscion.blob.v1") || 0x00 || u64_BE(length) || raw bytes).
- Snapshot digest = SHA-256(ASCII("openscion.snapshot.v1") || 0x00 || u64_BE(length) || canonical manifest bytes).
- IDs are exactly b1_ or s1_ plus 64 lower-case hex digits. Parsing is strict and object types cannot be interchanged.
- Storage: .openscion/objects/{b1|s1}/{first two hexadecimal digits}/{full 64-hex digest}, with type partitioning.
- Maximum blob size 16 MiB; maximum encoded snapshot size 8 MiB.

## Canonical manifest encoding

Magic 8 bytes ASCII OSNAP001, followed by u32_BE entry count. Each entry, in strictly increasing bytewise UTF-8 path order: u16_BE path byte length, path bytes, u8 executable mode (0 regular, 1 executable), 32 raw bytes of referenced blob digest. No trailing bytes, unknown modes, unresolved blob IDs, duplicate names, case collisions or ambiguous directory/file path prefixes. Entries can be supplied in any order; construction sorts before encoding.

## Portable path policy

ASCII only: letters, digits, dot, underscore, hyphen and forward slash. Max 1024 bytes and 64 nonempty components. Disallow absolute paths, backslash, colon, trailing dot, empty, "." or ".." components; reserve ".openscion" and ".git" components at every directory level; reject case-insensitive duplicates and conflicts between file and parent directory. Reject Windows device basenames CON/PRN/AUX/NUL/COM1..9/LPT1..9 even with extensions. Reject Unicode until a versioned normalization policy exists. Only regular files are represented; symbolic links/devices/etc are not v1 objects. This is a deliberate restriction, not equivalent to supporting every Git path.

## Local persistence invariants

1. Every object publication uses a uniquely created same-directory temporary file, owner-only by default on Unix, sync_all, then an atomic no-overwrite hard link to the digest path. Never use rename that can overwrite existing published objects.
2. Repeated writes of identical bytes are idempotent. If the object already exists and is corrupt, fail; never self-repair silently.
3. Validate every ancestor/shard/object as not symlink or Windows reparse point before use. Containment is **not** race-free against a malicious same-user actor replacing directories concurrently; later service architecture requires handle-relative operations.
4. Bound reads and writes. Always verify the digest on retrieval. Wrong-kind ID, tamper, missing object, dangling reference, unsafe path, invalid manifest or oversized payload => typed failure.
5. Verify FOSS-387 store format before object operations; missing/partial repository metadata => fail closed.
6. Interrupted writes leave no final digest name. Staging files are ignored on read and are not treated as verified objects; cleanup/GC is future work.
7. Materialization uses a newly allocated sibling staging directory, validates contents and expected blobs, writes files with create_new and sync, then renames staging to a nonexistent final directory. Existing destinations must never be overwritten. No revisions/channels are modified by a materialization.
8. On Unix, default directories 0700 and staged files 0600. Windows ACLs and crash durability require separate OS tests.

## Public API (subject to review)

ObjectStore::open(repository), put_blob(bytes), get_blob(id), put_snapshot(entries), get_snapshot(id), materialize(id, destination). ObjectId::parse(string) / Display. SnapshotEntry { path: String, blob: ObjectId, executable: bool }. CLI candidates: blob put/verify and snapshot put/show/materialize, which cannot promote revisions.

## Test requirements

CAS-001: same bytes/type => same ID; one-bit change => different ID
CAS-002: blob/snapshot type partition and domain separation
CAS-003: on-disk mutation rejected on read/verify
CAS-004: existing corrupt object never overwritten
CAS-005: truncated/uppercase/nonhex/wrong-kind ID refused
CAS-006: oversize blob/manifest rejected
CAS-007: permuted entries yield identical canonical ID and bytes
CAS-008: duplicate, case-colliding, traversal, device, Unicode, and file/dir prefix paths rejected
CAS-009: missing or corrupted referenced blob rejected on snapshot creation/read
CAS-010: invalid header, count, mode, trailing bytes, and unsorted entries rejected
CAS-011: materialized file bytes and executable mode match; no symlinks created
CAS-012: existing/symlink/unsafe destination does not get overwritten
CAS-013: malicious object-shard or object-file symlinks rejected
CAS-014: duplicate publishing is safe; concurrent identical writes never mutate final object
CAS-015: interrupted temporary write and restart do not expose partial final objects
CAS-016: no valid store marker means no writes
CAS-017: manual CLI inspection of object bytes, IDs, manifest and restoration

## Validation and dependencies

Commit spec/test sources before implementation and preserve commit order for audit. Execute Cargo compile/test/fmt/clippy individually and observe manual positive/negative command results on both Linux and Windows before merging either dependent PR. Archive raw logs, toolchain, SHA and hashes; no GitHub Actions. RustCrypto sha2 0.10.9 adds transitive dependencies requiring a generated Cargo.lock, license review, SBOM and audit before approval. No statement that source inspection is equivalent to passing Rust tests.