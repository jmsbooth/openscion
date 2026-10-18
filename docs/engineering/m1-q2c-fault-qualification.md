# FOSS-491 / M1-Q2C — Deterministic fault-boundary qualification

**Status: TEST TOOLING ONLY. Native Windows: NOT_RUN. Independent security signoff: NOT_OBTAINED.**

## Split implementation and trust boundary

The standard-library Python controller qa/qualification/m1_q2_cutpoints.py and its tests are a mainline QA-only increment. The separate draft Rust PR (test/foss-491-qa-cutpoints, stacked on PR #3) adds 12 explicit fault hooks at actual object and checkout publication transitions. The Rust feature qa-fault-injection is OFF by default, and builds with debug_assertions disabled must refuse to compile this feature. Do not distribute a QA-feature binary as a release binary. No source-control authority or promotion service is added.

At a selected source checkpoint, the debug-only Rust code writes/fsyncs one marker named <nonce>.<point>.hit containing a matching point, nonce, and process PID; the child pauses for at most 30 seconds. The controller requires exact event bytes/PID/point/nonce, then terminates the child, checks the expected published or unpublished state, and retries in a new process. An unknown or unreachable point is failure, not a timed-kill pass.

## Twelve checkpoints and observable assertions

| Rust checkpoint | Canonical publication immediately after kill |
|---|---|
| object_before_stage_fsync | Blob absent |
| object_after_stage_fsync | Blob absent |
| object_before_publish | Blob absent |
| object_after_publish | Blob present and valid |
| object_before_stage_remove | Blob present and valid |
| object_after_stage_remove | Blob present and valid |
| object_before_parent_sync | Blob present and valid |
| object_after_parent_sync | Blob present and valid |
| checkout_before_publish | Checkout absent |
| checkout_after_publish | Checkout present and correct |
| checkout_before_parent_sync | Checkout present and correct |
| checkout_after_parent_sync | Checkout present and correct |

**Windows persistence caveat:** The current sync_directory() is a no-op on Windows. A checkpoint named after_parent_sync is a program-position marker only, NOT proof that NTFS directory metadata was flushed. Process-kill/restart does not prove physical power-loss durability. Same-user TOCTOU and agent identity separation also remain unresolved (FOSS-487).

## Native Windows procedure — NOT_RUN

Requires a trusted native Windows host (local fixed NTFS), Rust 1.85.1 with MSVC/Cargo/Rustfmt/Clippy, Python 3.11+, PowerShell 7.4+, Git, and reviewed offline crates. The checked-out Rust QA-feature branch and the clean main checkout containing the Python helper must be separate. Use fresh evidence paths outside the source repo.

PowerShell (replace example paths with actual reviewed worktrees):

    $source = 'C:\src\openscion-cutpoints'
    $trusted = 'C:\src\openscion-main\qa\qualification'
    $sha = (git -C $source rev-parse HEAD).Trim()
    cargo build --manifest-path (Join-Path $source 'Cargo.toml') --package openscion-cli --locked --offline --features qa-fault-injection
    $exe = Join-Path $source 'target\debug\openscion.exe'
    $raw = 'C:\m1-evidence\q2c-raw-new'
    $packet = 'C:\m1-evidence\q2c-packet-new'
    python (Join-Path $trusted 'evidence.py') capture --repo $source --source-sha $sha --case cutpoints-native --output $packet --artifacts $raw --timeout 1200 -- python (Join-Path $trusted 'm1_q2_cutpoints.py') --repo $source --binary $exe --expected-sha $sha --evidence $raw --timeout 15
    python (Join-Path $trusted 'evidence.py') verify --packet (Split-Path -Parent $packet) --source-sha $sha --require cutpoints-native:Windows

The packet and raw path must not already exist, and their parents must exist on a local fixed NTFS drive without reparse-point ancestors. Run this once per exact PR head and repeat after stack reconciliation. Standard no-feature metadata/fmt/Clippy/workspace tests and native NTFS DACL/junction acceptance remain additional mandatory gates. Try a QA-feature release build expecting compile rejection, and build/verify a normal release separately.

The evidence packet is an untrusted integrity record, not signed host identity or independent approval. External native inspection and a distinct authorized reviewer must validate the binary build, actual NTFS ACLs, source markers and recovery observations; any unsupported power-loss claims remain outside the acceptance boundary.

## Portable regressions (not native qualification)

    python3 -m unittest discover -s qa/qualification -p 'test_m1_q2_cutpoints.py' -v
    python3 -m py_compile qa/qualification/m1_q2_cutpoints.py

These tests cover fail-closed preflights, symlink and marker spoofing and four representative points using a fake POSIX executable. Passing them is not a Windows NTFS or actual Rust fault-injection result.
