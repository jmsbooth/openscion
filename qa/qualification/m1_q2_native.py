#!/usr/bin/env python3
"""Run M1-Q2 Rust/native Windows checks and capture raw per-command evidence.

This tool cannot attest host identity or substitute for independent security review.
"""
from __future__ import annotations

import argparse
import ctypes
from pathlib import Path
import platform
import re
import subprocess
import sys

HELPER = Path(__file__).with_name("evidence.py")
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
CHECKS: tuple[tuple[str, list[str]], ...] = (
    ("cargo-metadata", ["cargo", "metadata", "--locked", "--offline", "--format-version", "1"]),
    ("rust-fmt", ["cargo", "fmt", "--all", "--", "--check"]),
    ("rust-tests", ["cargo", "test", "--workspace", "--locked", "--offline", "--", "--nocapture"]),
    ("rust-clippy", ["cargo", "clippy", "--workspace", "--all-targets", "--locked", "--offline", "--", "-D", "warnings"]),
    ("rust-build", ["cargo", "build", "--workspace", "--locked", "--offline"]),
)


def require_native_ntfs(root: Path) -> None:
    """Preflight only: a human must independently attest native Windows/NTFS."""
    if sys.platform != "win32" or platform.system() != "Windows":
        raise RuntimeError("NOT_RUN: requires an actual Windows host, not cross-compilation")
    if root.drive.startswith("\\\\") or not root.drive:
        raise RuntimeError("NOT_RUN: local drive letter required for evidence")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
    kernel.GetDriveTypeW.restype = ctypes.c_uint32
    drive_root = root.anchor
    if kernel.GetDriveTypeW(drive_root) != 3:  # DRIVE_FIXED
        raise RuntimeError("NOT_RUN: evidence must be on a local fixed drive")
    fs_name = ctypes.create_unicode_buffer(64)
    kernel.GetVolumeInformationW.argtypes = [
        ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_uint32,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_wchar_p, ctypes.c_uint32,
    ]
    kernel.GetVolumeInformationW.restype = ctypes.c_int
    if not kernel.GetVolumeInformationW(drive_root, None, 0, None, None, None, fs_name, 64):
        raise RuntimeError("NOT_RUN: cannot inspect native volume filesystem")
    if fs_name.value != "NTFS":
        raise RuntimeError("NOT_RUN: NTFS required")


def run(args: argparse.Namespace) -> int:
    if not HEX40.fullmatch(args.expected_sha):
        raise ValueError("expected-sha must be a canonical Git commit SHA")
    repo = Path(args.repo).resolve(strict=True)
    output = Path(args.output).absolute()
    if not output.parent.is_dir() or output.exists():
        raise ValueError("new packet path under an existing directory is required")
    if output == repo or repo in output.parents:
        raise ValueError("evidence must be outside the source repository")
    require_native_ntfs(output.parent)
    if not HELPER.is_file():
        raise RuntimeError("the separately merged FOSS-488 evidence helper is required")
    head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                          capture_output=True, text=True, check=True).stdout.strip()
    dirty = subprocess.run(["git", "-C", str(repo), "status", "--porcelain", "--untracked-files=all"],
                           capture_output=True, text=True, check=True).stdout
    if head != args.expected_sha or dirty:
        raise RuntimeError("wrong Git source head or dirty checkout")
    if not (repo / "Cargo.toml").is_file():
        raise RuntimeError("missing Cargo workspace")
    if args.suite in ("cas", "revision") and not (repo / "qa/windows/M1-Qualification.ps1").is_file():
        raise RuntimeError("native NTFS runner not present on this revision")
    # After validation, capture each command independently. A failure leaves
    # the partial packet for diagnostics, but never reports qualification.
    output.mkdir()
    cases = []
    for name, command in CHECKS:
        cases.append(name)
        cmd = [sys.executable, str(HELPER), "capture", "--repo", str(repo),
               "--source-sha", head, "--output", str(output / name),
               "--case", name, "--timeout", "1200", "--", *command]
        if subprocess.run(cmd, check=False).returncode != 0:
            raise RuntimeError(f"{name} failed; inspect partial raw evidence packet")
    # Independently exercise the native .exe on a disposable NTFS root. These
    # smoke cases are required even for the CLI-only PR #2.
    binary = repo / "target/debug/openscion.exe"
    if not binary.is_file():
        raise RuntimeError("native Windows executable missing after Cargo build")
    fixture = output.parent / f"{output.name}-cli-{head[:12]}"
    if fixture.exists():
        raise ValueError("refusing to reuse CLI fixture")
    fixture.mkdir()
    smoke = (
        ("cli-before-init", [str(binary), "status", "--json", str(fixture)], 4),
        ("cli-init", [str(binary), "init", "--json", str(fixture)], 0),
        ("cli-after-init", [str(binary), "status", "--json", str(fixture)], 0),
    )
    for name, command, expected_exit in smoke:
        cmd = [sys.executable, str(HELPER), "capture", "--repo", str(repo),
               "--source-sha", head, "--output", str(output / name),
               "--case", name, "--expect-exit", str(expected_exit), "--timeout", "120",
               "--", *command]
        if subprocess.run(cmd, check=False).returncode != 0:
            raise RuntimeError(f"{name} failed; native CLI smoke qualification incomplete")
        cases.append(name)
    if args.suite in ("cas", "revision"):
        name = "native-ntfs"
        artifact_dir = output.parent / f"{output.name}-raw-{head[:12]}"
        if artifact_dir.exists():
            raise ValueError("refusing to overwrite existing raw native artifacts")
        runner = ["pwsh", "-NoProfile", "-File", str(repo / "qa/windows/M1-Qualification.ps1"),
                  "-Binary", str(repo / "target/debug/openscion.exe"),
                  "-SourceRoot", str(repo), "-ExpectedHead", head,
                  "-ArtifactDir", str(artifact_dir), "-Contenders", "20"]
        cmd = [sys.executable, str(HELPER), "capture", "--repo", str(repo),
               "--source-sha", head, "--output", str(output / name),
               "--case", name, "--timeout", "1200", "--artifacts", str(artifact_dir),
               "--", *runner]
        if subprocess.run(cmd, check=False).returncode != 0:
            raise RuntimeError("native-ntfs failed; do not qualify this revision")
        cases.append(name)
    cmd = [sys.executable, str(HELPER), "verify", "--packet", str(output),
           "--source-sha", head]
    for name in cases:
        cmd.extend(["--require", f"{name}:Windows"])
    if subprocess.run(cmd, check=False).returncode != 0:
        raise RuntimeError("evidence-integrity verification failed")
    print("M1-Q2 test transcripts captured; independent security signoff still required")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="clean checkout of exact PR revision")
    parser.add_argument("--expected-sha", required=True, help="verified 40-character Git commit")
    parser.add_argument("--output", required=True, help="new external evidence packet directory")
    parser.add_argument("--suite", choices=("cli", "cas", "revision"), required=True)
    args = parser.parse_args()
    try:
        return run(args)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"E_M1_Q2_BLOCKED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
