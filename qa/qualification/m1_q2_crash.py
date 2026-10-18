#!/usr/bin/env python3
"""Windows observational process-kill/restart tests for the immutable blob store.

IMPORTANT: This is not deterministic publication-boundary injection or a power-loss test.
Outputs raw per-attempt transcripts for independent inspection; never certifies M1.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import time

HEX40 = set("0123456789abcdef")
DELAYS_MS = (0, 1, 5, 25)
MAX_ATTEMPTS = 128
BLOB_BYTES = 1024 * 1024


class Blocked(Exception):
    """Qualification preconditions or a recovery assertion failed."""


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise Blocked(reason)


def strict_head(repo: Path, expected_sha: str) -> None:
    require(len(expected_sha) == 40 and set(expected_sha) <= HEX40,
            "source SHA must be 40 lowercase hexadecimal characters")
    root = subprocess.run(["git", "-C", str(repo), "rev-parse", "--show-toplevel"],
                          capture_output=True, text=True, check=True).stdout.strip()
    require(Path(root).resolve() == repo.resolve(), "repo must be the Git checkout root")
    head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                          capture_output=True, text=True, check=True).stdout.strip()
    dirty = subprocess.run(["git", "-C", str(repo), "status", "--porcelain", "--untracked-files=all"],
                           capture_output=True, text=True, check=True).stdout
    require(head == expected_sha and not dirty, "source commit changed or worktree is dirty")


def require_windows_ntfs(path: Path) -> None:
    require(sys.platform == "win32" and platform.system() == "Windows",
            "NOT_RUN: requires actual native Windows, not WSL/Wine")
    # Import only on native Windows. Remote and UNC volumes must not qualify.
    import ctypes
    require(bool(path.drive) and not path.drive.startswith("\\\\"),
            "NOT_RUN: evidence must use a local drive letter")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
    kernel.GetDriveTypeW.restype = ctypes.c_uint32
    require(kernel.GetDriveTypeW(path.anchor) == 3, "NOT_RUN: a fixed local drive is required")
    label = ctypes.create_unicode_buffer(64)
    kernel.GetVolumeInformationW.argtypes = [ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_uint32,
                                             ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                             ctypes.c_wchar_p, ctypes.c_uint32]
    kernel.GetVolumeInformationW.restype = ctypes.c_int
    require(bool(kernel.GetVolumeInformationW(path.anchor, None, 0, None, None, None, label, 64)),
            "NOT_RUN: cannot inspect local filesystem")
    require(label.value == "NTFS", "NOT_RUN: NTFS required")


def reject_linked_ancestors(path: Path) -> None:
    """Refuse junction/reparse/symlink ancestors for Windows evidence paths."""
    candidate = path
    while True:
        try:
            meta = candidate.lstat()
        except FileNotFoundError:
            pass
        else:
            reparse = getattr(meta, "st_file_attributes", 0) & 0x400
            require(not candidate.is_symlink() and not reparse,
                    "NOT_RUN: evidence/fixture path traverses a reparse point")
        if candidate == candidate.parent:
            return
        candidate = candidate.parent


def payload(index: int) -> bytes:
    seed = hashlib.sha256(f"openscion-crash-{index:04d}".encode()).digest()
    return seed * (BLOB_BYTES // len(seed))


def execute(binary: Path, args: list[str], timeout: float = 30) -> tuple[int, bytes, bytes]:
    # Use files, not capture_output=True: a hostile or broken binary must not
    # cause unbounded Python heap usage while the subprocess is running.
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        proc = subprocess.run([str(binary), *args], check=False,
                              stdout=stdout, stderr=stderr, timeout=timeout)
        require(stdout.tell() <= 131072 and stderr.tell() <= 131072,
                "native CLI generated oversized response streams")
        stdout.seek(0)
        stderr.seek(0)
        return proc.returncode, stdout.read(), stderr.read()


def assert_ok_json(result: tuple[int, bytes, bytes], command: str) -> dict:
    rc, stdout, stderr = result
    require(rc == 0 and len(stdout) <= 131072 and len(stderr) <= 131072,
            f"{command}: failed or oversized CLI transcript (exit={rc})")
    try:
        data = json.loads(stdout)
    except (UnicodeError, ValueError) as error:
        raise Blocked(f"{command}: invalid JSON output") from error
    require(type(data) is dict and data.get("ok") is True and data.get("command") == command,
            f"{command}: unexpected CLI success contract")
    return data


def preflight(args: argparse.Namespace) -> tuple[Path, Path, Path, Path]:
    repo = Path(args.repo).resolve(strict=True)
    binary = Path(args.binary).resolve(strict=True)
    artifact = Path(args.artifacts).absolute()
    fixture = Path(args.fixture).absolute()
    require(1 <= args.attempts <= MAX_ATTEMPTS, "attempt count out of bounds")
    require(artifact != fixture and artifact not in fixture.parents and fixture not in artifact.parents,
            "fixture and evidence must be separate directories")
    require(not artifact.exists() and not fixture.exists() and
            not artifact.is_symlink() and not fixture.is_symlink(),
            "refusing to overwrite previous evidence or fixture")
    reject_linked_ancestors(artifact)
    reject_linked_ancestors(fixture)
    require(artifact.parent.is_dir() and fixture.parent.is_dir(), "both output parents must exist")
    require(not artifact.is_relative_to(repo) and not fixture.is_relative_to(repo),
            "do not mutate or write evidence within source checkout")
    require_windows_ntfs(artifact.parent)
    require_windows_ntfs(fixture.parent)
    strict_head(repo, args.expected_sha)
    require(binary.is_file() and binary.suffix.lower() == ".exe", "native executable missing")
    require(binary == (repo / "target/debug/openscion.exe").resolve(),
            "native executable must be the workspace Cargo build output")
    return repo, binary, artifact, fixture


def run(args: argparse.Namespace) -> dict:
    repo, binary, artifact, fixture = preflight(args)
    artifact.mkdir()
    fixture.mkdir()
    code_file = fixture / "source.bin"
    assert_ok_json(execute(binary, ["init", "--json", str(fixture)]), "init")
    observations: list[dict] = []
    killed_count = 0
    observed_completion = 0
    for iteration in range(args.attempts):
        strict_head(repo, args.expected_sha)
        data = payload(iteration)
        with code_file.open("wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        ms = DELAYS_MS[iteration % len(DELAYS_MS)]
        # Redirect to files to prevent pipe deadlock or unbounded in-memory streams.
        stdout = artifact / f"attempt-{iteration:03d}.stdout"
        stderr = artifact / f"attempt-{iteration:03d}.stderr"
        start = time.monotonic()
        with stdout.open("xb") as out, stderr.open("xb") as err:
            process = subprocess.Popen([str(binary), "blob", "put", "--json",
                                        str(fixture), "source.bin"], stdout=out, stderr=err)
            time.sleep(ms / 1000)
            interrupted = process.poll() is None
            if interrupted:
                process.kill()
                killed_count += 1
            else:
                observed_completion += 1
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired as exc:
                process.kill()
                process.wait(timeout=5)
                raise Blocked(f"attempt {iteration}: subprocess did not terminate") from exc
            out.flush()
            err.flush()
            os.fsync(out.fileno())
            os.fsync(err.fileno())
        duration_ms = int((time.monotonic() - start) * 1000)
        initial_id = None
        if not interrupted:
            # A successful natural completion is part of the contract too;
            # silently ignoring failures here would produce false evidence.
            initial = assert_ok_json((process.returncode, stdout.read_bytes(),
                                      stderr.read_bytes()), "blob put")
            initial_id = initial.get("id")
        else:
            require(process.returncode != 0,
                    f"attempt {iteration}: interruption claimed but process exited cleanly")
        # A subsequent fresh process must be able to write the same immutable
        # content or retrieve the already-published object after a crash.
        repaired = assert_ok_json(execute(binary, ["blob", "put", "--json",
                                                   str(fixture), "source.bin"]), "blob put")
        blob_id = repaired.get("id")
        require(isinstance(blob_id, str) and blob_id.startswith("b1_") and len(blob_id) == 67
                and set(blob_id[3:]) <= HEX40, f"attempt {iteration}: invalid immutable blob ID")
        if initial_id is not None:
            require(initial_id == blob_id, f"attempt {iteration}: natural and retry IDs diverge")
        verified = assert_ok_json(execute(binary, ["blob", "verify", "--json",
                                                   str(fixture), blob_id]), "blob verify")
        require(verified.get("id") == blob_id and verified.get("bytes") == len(data),
                f"attempt {iteration}: incorrect fresh-process readback")
        observations.append({"attempt": iteration, "delay_ms": ms, "interrupted": interrupted,
                             "exit_code": process.returncode, "elapsed_ms": duration_ms,
                             "source_sha256": hashlib.sha256(data).hexdigest(),
                             "blob_id": blob_id, "retry_verified": True})
    strict_head(repo, args.expected_sha)
    report = {"schema": "openscion.qa.windows-crash-observation.v1",
              "source_sha": args.expected_sha,
              "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
              "attempts": args.attempts, "interrupted_count": killed_count,
              "natural_completions": observed_completion,
              "boundary_injection": False, "power_loss_verified": False,
              "independent_security_review": "not_obtained",
              "observations": observations}
    (artifact / "summary.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    require(killed_count > 0, "no process was actually interrupted: unqualified run")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--artifacts", required=True, help="NEW external raw evidence directory")
    parser.add_argument("--fixture", required=True, help="NEW disposable NTFS repository")
    parser.add_argument("--attempts", type=int, default=64)
    args = parser.parse_args()
    try:
        result = run(args)
        print(json.dumps({"status": "observational_only", "source_sha": result["source_sha"],
                          "attempts": result["attempts"], "interrupted": result["interrupted_count"],
                          "boundary_injection": False, "independent_security_review": "not_obtained"}))
        return 0
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError, Blocked) as error:
        print(f"E_CRASH_QUALIFICATION: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
