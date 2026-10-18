#!/usr/bin/env python3
"""Deterministic M1-Q2C fault-boundary *observation* controller.

Only run on native Windows with a specifically built debug/QA Rust executable.
Checkpoint receipt is source-event evidence, not independent host attestation.
No physical power-loss / production-durability claims are made.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import subprocess
import sys
import tempfile
import time

POINTS: dict[str, bool] = {
    "object_before_stage_fsync": False,
    "object_after_stage_fsync": False,
    "object_before_publish": False,
    "object_after_publish": True,
    "object_before_stage_remove": True,
    "object_after_stage_remove": True,
    "object_before_parent_sync": True,
    "object_after_parent_sync": True,
    "checkout_before_publish": False,
    "checkout_after_publish": True,
    "checkout_before_parent_sync": True,
    "checkout_after_parent_sync": True,
}
SHA = re.compile(r"[0-9a-f]{40}\Z")
BLOB_ID = re.compile(r"b1_[0-9a-f]{64}\Z")
SNAPSHOT_ID = re.compile(r"s1_[0-9a-f]{64}\Z")
ENV_KEYS = ("OPENSCION_QA_CUTPOINT", "OPENSCION_QA_MARKER_DIR", "OPENSCION_QA_NONCE")
PAYLOAD = b"OpenScion M1-Q2C disposable fixture\n" * 4096


class QualificationError(RuntimeError):
    """The test did not meet its explicit evidence contract."""


def require(ok: bool, explanation: str) -> None:
    if not ok:
        raise QualificationError(explanation)


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def clean_environment() -> dict[str, str]:
    clean = os.environ.copy()
    for key in ENV_KEYS:
        clean.pop(key, None)
    return clean


def source_state(repo: Path, sha: str) -> None:
    require(bool(SHA.fullmatch(sha)), "expected SHA must be lowercase 40-hex")
    root = subprocess.run(["git", "-C", str(repo), "rev-parse", "--show-toplevel"],
                          check=True, capture_output=True, text=True).stdout.strip()
    require(Path(root).resolve() == repo.resolve(), "repo must equal git checkout root")
    head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                          check=True, capture_output=True, text=True).stdout.strip()
    dirty = subprocess.run(["git", "-C", str(repo), "status", "--porcelain", "--untracked-files=all"],
                           check=True, capture_output=True, text=True).stdout
    require(head == sha and not dirty, "wrong source revision or dirty checkout")


def ensure_nolinks(path: Path) -> None:
    candidate = path
    while True:
        try:
            attributes = candidate.lstat()
        except FileNotFoundError:
            pass
        else:
            require(not candidate.is_symlink()
                    and not getattr(attributes, "st_file_attributes", 0) & 0x400,
                    "evidence path crosses reparse point or symlink")
        if candidate == candidate.parent:
            return
        candidate = candidate.parent


def native_ntfs(path: Path) -> None:
    require(sys.platform == "win32" and platform.system() == "Windows",
            "NOT_RUN: real native Windows required")
    require(bool(path.drive) and not path.drive.startswith("\\\\"),
            "NOT_RUN: a local drive-letter volume is required")
    import ctypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
    kernel.GetDriveTypeW.restype = ctypes.c_uint32
    require(kernel.GetDriveTypeW(path.anchor) == 3, "NOT_RUN: fixed local disk required")
    fs_name = ctypes.create_unicode_buffer(64)
    kernel.GetVolumeInformationW.argtypes = [ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_uint32,
                                             ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                             ctypes.c_wchar_p, ctypes.c_uint32]
    kernel.GetVolumeInformationW.restype = ctypes.c_int
    require(bool(kernel.GetVolumeInformationW(path.anchor, None, 0, None, None, None, fs_name, 64)),
            "NOT_RUN: cannot inspect local volume")
    require(fs_name.value == "NTFS", "NOT_RUN: NTFS filesystem required")


def preflight(args: argparse.Namespace) -> tuple[Path, Path, Path]:
    require(1 <= args.timeout <= 30, "point timeout must be between 1 and 30 seconds")
    repo = Path(args.repo).resolve(strict=True)
    binary = Path(args.binary).resolve(strict=True)
    evidence = Path(args.evidence).absolute()
    require(not evidence.exists() and evidence.parent.is_dir(),
            "evidence must be a fresh path under an existing parent")
    require(not evidence.is_relative_to(repo), "evidence must be outside source checkout")
    ensure_nolinks(evidence)
    native_ntfs(evidence.parent)
    source_state(repo, args.expected_sha)
    require((repo / "Cargo.lock").is_file(), "Cargo.lock must exist at qualified revision")
    require(binary.is_file() and binary == (repo / "target/debug/openscion.exe").resolve(),
            "binary must be the native workspace debug CLI")
    return repo, binary, evidence


def cli_json(binary: Path, args: list[str]) -> tuple[int, dict]:
    # Run commands with no QA checkpoint environment to prevent accidental hangs.
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.run([str(binary), *args], env=clean_environment(), check=False,
                                 stdout=stdout, stderr=stderr, timeout=30)
        require(stdout.tell() <= 65536 and stderr.tell() <= 65536,
                "CLI output exceeded bound")
        stdout.seek(0)
        raw = stdout.read()
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise QualificationError("CLI emitted invalid JSON") from exc
    require(type(data) is dict and type(data.get("ok")) is bool, "invalid CLI response contract")
    return process.returncode, data


def must_succeed(binary: Path, args: list[str], command: str) -> dict:
    rc, data = cli_json(binary, args)
    require(rc == 0 and data.get("ok") is True and data.get("command") == command,
            f"{command}: unexpected return code or JSON response")
    return data


def marker_path(directory: Path, nonce: str, point: str) -> Path:
    require(point in POINTS and bool(re.fullmatch(r"[0-9a-f]{32}", nonce)), "unsafe point or nonce")
    return directory / f"{nonce}.{point}.hit"


def validate_marker(path: Path, point: str, nonce: str, pid: int) -> str:
    require(path.exists() and path.is_file() and not path.is_symlink(),
            "missing/linked checkpoint receipt")
    stats = path.lstat()
    require(not getattr(stats, "st_file_attributes", 0) & 0x400 and 0 < stats.st_size <= 512,
            "invalid checkpoint receipt type or length")
    data = path.read_bytes()
    expected = f"v1\npoint={point}\nnonce={nonce}\npid={pid}\n".encode("ascii")
    require(data == expected, "checkpoint receipt does not match expected point, nonce, PID")
    return hashlib.sha256(data).hexdigest()


def controlled_kill(binary: Path, arguments: list[str], evidence: Path,
                    point: str, nonce: str, timeout: int) -> dict:
    signal_dir = evidence / f"signal-{point}"
    signal_dir.mkdir()
    log_out = evidence / f"{point}.stdout"
    log_err = evidence / f"{point}.stderr"
    env = clean_environment()
    env.update({"OPENSCION_QA_CUTPOINT": point,
                "OPENSCION_QA_MARKER_DIR": str(signal_dir),
                "OPENSCION_QA_NONCE": nonce})
    started = time.monotonic()
    marker = marker_path(signal_dir, nonce, point)
    with log_out.open("xb") as out, log_err.open("xb") as err:
        process = subprocess.Popen([str(binary), *arguments], env=env, stdout=out, stderr=err)
        try:
            while not marker.exists():
                if process.poll() is not None:
                    raise QualificationError(f"{point}: process exited without reaching cutpoint")
                if time.monotonic() - started > timeout:
                    raise QualificationError(f"{point}: cutpoint never observed before timeout")
                time.sleep(0.010)
            marker_digest = validate_marker(marker, point, nonce, process.pid)
            require(process.poll() is None, "process left cutpoint without external kill")
            process.kill()
            process.wait(timeout=5)
            require(process.returncode != 0, "fault process exited normally")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            out.flush()
            err.flush()
            os.fsync(out.fileno())
            os.fsync(err.fileno())
    require(log_out.stat().st_size <= 65536 and log_err.stat().st_size <= 65536,
            "fault process log exceeded bound")
    return {"point": point, "pid": process.pid, "exit_code": process.returncode,
            "receipt_sha256": marker_digest, "elapsed_ms": int((time.monotonic()-started)*1000),
            "checkpoint_observed": True}


def blob_path(root: Path, object_id: str) -> Path:
    require(bool(BLOB_ID.fullmatch(object_id)), "invalid canonical blob ID")
    return root / ".openscion" / "objects" / "b1" / object_id[3:5] / object_id[3:]


def baseline_blob(binary: Path, fixture: Path) -> str:
    fixture.mkdir()
    must_succeed(binary, ["init", "--json", str(fixture)], "init")
    (fixture / "source.bin").write_bytes(PAYLOAD)
    put = must_succeed(binary, ["blob", "put", "--json", str(fixture), "source.bin"], "blob put")
    blob_id = put.get("id")
    require(type(blob_id) is str and bool(BLOB_ID.fullmatch(blob_id)), "wrong blob identity")
    return blob_id


def observe_one(binary: Path, evidence: Path, point: str, timeout: int) -> dict:
    fixture = evidence / f"fixture-{point}"
    fixture.mkdir()
    must_succeed(binary, ["init", "--json", str(fixture)], "init")
    (fixture / "source.bin").write_bytes(PAYLOAD)
    nonce = secrets.token_hex(16)
    if point.startswith("object_"):
        # Baseline object identity is measured on a separate clean repo, never
        # by writing into the fixture to be fault-injected.
        baseline = evidence / f"baseline-{point}"
        baseline_id = baseline_blob(binary, baseline)
        target = blob_path(fixture, baseline_id)
        args = ["blob", "put", "--json", str(fixture), "source.bin"]
        receipt = controlled_kill(binary, args, evidence, point, nonce, timeout)
        expected_published = POINTS[point]
        actual = target.exists()
        require(actual == expected_published,
                f"{point}: published blob visibility does not match fault boundary")
        if actual:
            must_succeed(binary, ["blob", "verify", "--json", str(fixture), baseline_id], "blob verify")
        result = must_succeed(binary, args, "blob put")
        require(result.get("id") == baseline_id, f"{point}: retry changed object identity")
        verified = must_succeed(binary, ["blob", "verify", "--json", str(fixture), baseline_id], "blob verify")
        require(verified.get("id") == baseline_id and verified.get("bytes") == len(PAYLOAD),
                f"{point}: verified blob mismatch")
        require(target.read_bytes() == PAYLOAD, "published blob bytes changed after retry")
        receipt.update({"kind": "object", "visible_after_kill": actual,
                        "published_expected": expected_published, "object_id": baseline_id,
                        "retry_verified": True})
    else:
        source = must_succeed(binary, ["blob", "put", "--json", str(fixture), "source.bin"], "blob put")
        blob_id = source.get("id")
        require(type(blob_id) is str and bool(BLOB_ID.fullmatch(blob_id)), "wrong blob identity")
        (fixture / "manifest.tsv").write_text(f"source.bin\t{blob_id}\t0\n", encoding="ascii")
        snapshot = must_succeed(binary, ["snapshot", "put", "--json", str(fixture), "manifest.tsv"], "snapshot put")
        snapshot_id = snapshot.get("id")
        require(type(snapshot_id) is str and bool(SNAPSHOT_ID.fullmatch(snapshot_id)), "wrong snapshot identity")
        target = fixture / "checkout"
        args = ["snapshot", "materialize", "--json", str(fixture), snapshot_id, str(target)]
        receipt = controlled_kill(binary, args, evidence, point, nonce, timeout)
        expected_published = POINTS[point]
        actual = target.exists()
        require(actual == expected_published,
                f"{point}: checkout visibility does not match fault boundary")
        if expected_published:
            rc, data = cli_json(binary, args)
            require(rc == 5 and data == {"ok": False, "code": "E_ALREADY_EXISTS"},
                    f"{point}: retry overwrote published checkout")
        else:
            must_succeed(binary, args, "snapshot materialize")
        require((target / "source.bin").read_bytes() == PAYLOAD,
                f"{point}: published checkout content incorrect")
        receipt.update({"kind": "checkout", "visible_after_kill": actual,
                        "published_expected": expected_published,
                        "snapshot_id": snapshot_id, "retry_verified": True})
    return receipt


def run(args: argparse.Namespace) -> dict:
    repo, binary, evidence = preflight(args)
    evidence.mkdir()
    observed: list[dict] = []
    failure = None
    try:
        for point in POINTS:
            source_state(repo, args.expected_sha)
            observed.append(observe_one(binary, evidence, point, args.timeout))
        source_state(repo, args.expected_sha)
    except (QualificationError, OSError, subprocess.SubprocessError, ValueError) as exc:
        failure = str(exc)
    report = {"schema": "openscion.qa.cutpoints.v1", "source_sha": args.expected_sha,
              "binary_sha256": hash_file(binary), "cargo_lock_sha256": hash_file(repo / "Cargo.lock"),
              "host_system": platform.system(), "observations": observed,
              "planned_count": len(POINTS), "completed_count": len(observed),
              "status": "observed" if failure is None and len(observed) == len(POINTS) else "failed",
              "error": failure, "deterministic_checkpoint_observation": len(observed) == len(POINTS) and failure is None,
              "physical_power_loss_verified": False, "independent_review": "not_obtained",
              "host_attestation": "not_provided"}
    (evidence / "summary.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    require(report["status"] == "observed", f"unqualified native checkpoint run: {failure}")
    print(json.dumps({"status": report["status"], "count": len(observed),
                      "independent_review": "not_obtained", "physical_power_loss_verified": False}))
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--evidence", required=True, help="new external directory on fixed NTFS")
    parser.add_argument("--timeout", type=int, default=15)
    args = parser.parse_args()
    try:
        run(args)
        return 0
    except (QualificationError, OSError, subprocess.SubprocessError, ValueError) as exc:
        print(f"E_CUTPOINT_QUALIFICATION: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
