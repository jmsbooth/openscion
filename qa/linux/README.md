# OpenScion M1 — Deterministic Linux process-kill qualification

**Scope:** FOSS-398/FOSS-465 Linux runtime qualification; NOT production code, NOT electrical power loss, NOT Windows. No GitHub Actions.

This is a test-first, external injection harness. A Linux-only LD_PRELOAD shim intercepts the existing OpenScion CLI's `fsync` and `linkat` boundary calls. It blocks at a named checkpoint and signals a **separate supervisor**, which sends actual SIGKILL. Production Rust code contains no test flags or crash hooks.

## Preconditions

- Native Linux (GNU/glibc, dynamically linked OpenScion binary), Rust toolchain pinned by `rust-toolchain.toml`, Python >=3.10, C compiler (`cc` or Zig `zig cc` wrapper).
- Use **only disposable fixture repositories** created by the driver. Do not supply a live user repository or production source.
- Prefer ext4/XFS for storage qualification; record the actual mount and filesystem. A container/overlay run is evidence for that host only.
- Fetch reviewed crates once on an approved workstation, then use the committed `Cargo.lock` and `--locked --offline` for qualification.
- No CI runs; inspect each compiler/test command and preserve terminal output, exit status and checksum.

## Commands — run and inspect individually

```sh
git rev-parse HEAD
rustc --version
cargo --version
cargo fetch --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked --offline --target x86_64-unknown-linux-gnu -- -D warnings
cargo test --workspace --locked --offline --target x86_64-unknown-linux-gnu -- --nocapture
cargo build --workspace --locked --offline --target x86_64-unknown-linux-gnu

# For Zig as C compiler: create a local wrapper, e.g. exec /opt/zig/zig cc "$@".
# Or omit --cc when a working native gcc/clang cc is installed.
python3 qa/linux/crash_qualification.py \
  --binary target/x86_64-unknown-linux-gnu/debug/openscion \
  --cc /usr/bin/cc \
  --iterations 10 --contenders 20 \
  --artifacts /tmp/openscion-m1-crash-evidence
```

Inspect `summary.json`, `*.stdout`, `*.stderr`, `barrier.ready`, `fixture/` metadata and the unique immutable object paths. The harness asserts **actual SIGKILL** and restarts a new CLI process; missing barriers and wrong signal are FAIL, not skipped/pass.

### Fault points

| Point | Expected state at SIGKILL |
|---|---|
| `blob-before-stage-fsync` | No published blob; recover by retry; private incomplete stage may remain |
| `blob-after-stage-fsync` | Stage synced, no published blob; recover by retry |
| `blob-before-link` | Fully staged, no published blob; recover by retry |
| `blob-after-link` | Published canonical blob already visible; idempotent retry must match |
| `blob-before-parent-fsync` | Blob published; parent flush not yet acknowledged; idempotent retry |
| `checkout-before-stage-fsync` | Output destination absent; stage may remain; retry must materialize |
| `checkout-after-publish` | Output destination already present; retry must reject overwrite |

Every test independently recomputes the domain-separated SHA-256 blob ID and verifies bytes/permissions. Concurrent tests require 20 identical blob importers to converge on a single ID, and 20 competing checkout publishers to produce precisely one success with 19 `E_ALREADY_EXISTS` rejections.

## Evidence archival and verification

The run on 2026-10-17 is archived under `docs/engineering/evidence/M1-linux-crash-2026-10-17.tar.gz.b64.part00` through `.part03`. They are consecutive **base64 text segments of one gzip tarball**, not separate compressed files.

```sh
cat docs/engineering/evidence/M1-linux-crash-2026-10-17.tar.gz.b64.part0* \
  | base64 --decode > /tmp/M1-linux-crash-2026-10-17.tar.gz
sha256sum /tmp/M1-linux-crash-2026-10-17.tar.gz
# Expected: 9e4232146b57992c4b63871f07e73a17bfd2fa18a01079a6fc0dfa620876c730
mkdir -p /tmp/openscion-evidence-inspection
tar -tzf /tmp/M1-linux-crash-2026-10-17.tar.gz | head -30
tar -xzf /tmp/M1-linux-crash-2026-10-17.tar.gz -C /tmp/openscion-evidence-inspection
sha256sum /tmp/openscion-evidence-inspection/summary.json
# Expected: a6b8713c945ae884a4634d67bc18854a086b4134fe2d7d85b44956af822e449d
```

The archive contains raw stdout/stderr, per-attempt sentinels, a SHA-256-indexed `summary.json`, and the test-only compiled shared object. The sandbox artifact has no signing authority: independent reviewers must reproduce and attest their own observations.

## Limitations / release implications

- SIGKILL exercises process death, not kernel restart, torn writes or actual storage-controller power failure.
- LD_PRELOAD is specific to glibc-linked GNU/Linux. MUSL/static builds require a separate method. Linux filesystems differ; record actual ext4/XFS/overlay mount.
- Windows NTFS DACL, junction and reparse checks are NOT_RUN here. Use `qa/windows/M1-Qualification.ps1` on a real Windows NTFS host; **expect known DACL red tests until FOSS-484 is implemented**.
- Killed operations can leave private orphan stages even after correct recovery (FOSS-485). Do not implement unsafe age-only cleanup that might delete an active writer's stage.
- Local hash-chained evidence is not independently anchored, signed provenance or a protected promotion receipt. FOSS-390 remains gated.

**This harness adds no security privilege to production OpenScion and is never distributed as part of its Rust build.**
