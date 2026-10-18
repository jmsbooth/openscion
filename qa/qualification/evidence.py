#!/usr/bin/env python3
"""Portable integrity-only capture and verification of local test transcripts."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import time

SCHEMA = "openscion.qa.case.v1"
CASE_ID = re.compile(r"[a-z][a-z0-9-]{1,63}\Z", re.ASCII)
GIT_SHA = re.compile(r"[0-9a-f]{40}\Z", re.ASCII)
MAX_FILES = 512
MAX_BYTES = 64 * 1024 * 1024
EXPECTED_KEYS = {
    "schema", "case", "source_sha", "head_after", "clean_before",
    "clean_after", "host_system", "python_version", "command",
    "started_utc", "elapsed_ms", "expected_exit", "exit_code",
    "timed_out", "files", "artifacts",
}


class EvidenceError(Exception):
    """A capture or verification contract was not satisfied."""


def ensure(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def sha256_path(path: Path) -> dict[str, object]:
    h = hashlib.sha256()
    count = 0
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            h.update(block)
            count += len(block)
            ensure(count <= MAX_BYTES, "individual evidence file exceeds 64 MiB")
    return {"sha256": h.hexdigest(), "bytes": count}


def run_git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(repo), *args],
                            capture_output=True, text=True, check=False, timeout=30)
    ensure(result.returncode == 0, f"git {args[0]} failed")
    return result.stdout.strip()


def source_state(repo: Path) -> tuple[str, bool]:
    ensure(repo.is_dir(), "source repository does not exist")
    ensure(Path(run_git(repo, "rev-parse", "--show-toplevel")).resolve() == repo.resolve(),
           "repository argument must be the checkout root")
    head = run_git(repo, "rev-parse", "HEAD")
    status = run_git(repo, "status", "--porcelain", "--untracked-files=all")
    return head, not status


def ensure_sha(sha: str) -> None:
    ensure(bool(GIT_SHA.fullmatch(sha)), "expected source SHA must be 40 lowercase hex digits")


def case_name(value: str) -> None:
    ensure(bool(CASE_ID.fullmatch(value)), "invalid case ID")


def write_bytes(path: Path, data: bytes) -> None:
    with path.open("xb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def safe_files(root: Path) -> dict[str, Path]:
    """Enumerate regular evidence files, refusing symlinks and special nodes."""
    found: dict[str, Path] = {}
    if not root.exists():
        return found
    ensure(root.is_dir() and not root.is_symlink(), "artifact source is not a real directory")
    pending = [(root, "")]
    while pending:
        directory, prefix = pending.pop()
        for item in directory.iterdir():
            ensure(not item.is_symlink(), "symlink in evidence artifacts")
            ensure(not getattr(item, "is_junction", lambda: False)(), "junction in evidence artifacts")
            name = item.name
            ensure(name not in (".", "..") and not name.endswith((".", " "))
                   and "\x00" not in name, "unsafe artifact filename")
            relative = f"{prefix}/{name}" if prefix else name
            ensure(len(relative) <= 1024, "artifact name exceeds bound")
            if item.is_dir():
                pending.append((item, relative))
            else:
                ensure(item.is_file(), "non-regular evidence artifact")
                ensure(relative not in found, "duplicate evidence artifact")
                found[relative] = item
                ensure(len(found) <= MAX_FILES, "too many evidence artifacts")
    return found


def copy_artifacts(source: Path, dest: Path) -> dict[str, dict[str, object]]:
    found = safe_files(source)
    ensure(sum(p.stat().st_size for p in found.values()) <= MAX_BYTES,
           "artifact bundle exceeds 64 MiB")
    if found:
        dest.mkdir()
    manifest: dict[str, dict[str, object]] = {}
    for relative, path in sorted(found.items()):
        target = dest.joinpath(*relative.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        with path.open("rb") as src, target.open("xb") as output:
            shutil.copyfileobj(src, output, length=1024 * 1024)
            output.flush()
            os.fsync(output.fileno())
        manifest[relative] = sha256_path(target)
    return manifest


def capture(args: argparse.Namespace) -> None:
    case_name(args.case)
    ensure_sha(args.source_sha)
    ensure(args.timeout > 0 and args.timeout <= 3600, "timeout must be between 0 and 3600 seconds")
    ensure(0 <= args.expect_exit <= 255, "expected exit must be a process exit code")
    repo = Path(args.repo).resolve()
    output = Path(args.output).resolve()
    ensure(output.parent.is_dir() and output.parent != repo
           and not output.is_relative_to(repo), "evidence must be outside checkout")
    ensure(not output.exists(), "refusing to overwrite an existing case")
    head, clean = source_state(repo)
    ensure(head == args.source_sha, "source HEAD does not match requested SHA")
    ensure(clean, "source tree must be clean before capture")
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    ensure(bool(command), "a command after -- is required")
    output.mkdir(exist_ok=False)
    started = datetime.now(timezone.utc).isoformat()
    start = time.monotonic()
    timed_out = False
    exit_code: int | None = None
    with (output / "stdout.bin").open("xb") as stdout, \
         (output / "stderr.bin").open("xb") as stderr:
        try:
            completed = subprocess.run(command, cwd=repo, stdout=stdout,
                                       stderr=stderr, check=False, timeout=args.timeout)
            exit_code = completed.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
        finally:
            stdout.flush()
            stderr.flush()
            os.fsync(stdout.fileno())
            os.fsync(stderr.fileno())
    head_after, clean_after = source_state(repo)
    artifacts: dict[str, dict[str, object]] = {}
    if args.artifacts:
        raw_artifacts = Path(args.artifacts)
        ensure(raw_artifacts.is_dir() and not raw_artifacts.is_symlink()
               and not getattr(raw_artifacts, "is_junction", lambda: False)(),
               "requested artifact directory is unavailable or linked")
        artifact_source = raw_artifacts.resolve()
        ensure(not artifact_source.is_relative_to(output), "cannot capture the output as its artifact source")
        artifacts = copy_artifacts(artifact_source, output / "artifacts")
    entry: dict[str, object] = {
        "schema": SCHEMA, "case": args.case, "source_sha": head,
        "head_after": head_after, "clean_before": clean,
        "clean_after": clean_after, "host_system": platform.system(),
        "python_version": platform.python_version(), "command": command,
        "started_utc": started, "elapsed_ms": int((time.monotonic() - start) * 1000),
        "expected_exit": args.expect_exit, "exit_code": exit_code,
        "timed_out": timed_out,
        "files": {name: sha256_path(output / name)
                  for name in ("stdout.bin", "stderr.bin")},
        "artifacts": artifacts,
    }
    write_bytes(output / "metadata.json", (json.dumps(entry, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    ensure(not timed_out and exit_code == args.expect_exit
           and head_after == head and clean_after, "captured test did not satisfy its declared contract")
    print(json.dumps({"case": args.case, "source_sha": head, "status": "captured"}, sort_keys=True))


def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    obj: dict[str, object] = {}
    for key, value in pairs:
        ensure(key not in obj, "duplicate JSON key")
        obj[key] = value
    return obj


def check_digest(path: Path, recorded: object) -> None:
    ensure(path.is_file() and not path.is_symlink(), "missing or symlinked evidence file")
    ensure(isinstance(recorded, dict) and set(recorded) == {"sha256", "bytes"},
           "invalid digest record")
    ensure(isinstance(recorded["sha256"], str) and
           re.fullmatch(r"[0-9a-f]{64}", recorded["sha256"]) is not None,
           "invalid digest format")
    ensure(type(recorded["bytes"]) is int and 0 <= recorded["bytes"] <= MAX_BYTES,
           "invalid byte length")
    ensure(sha256_path(path) == recorded, "evidence bytes do not match recorded digest")


def verify_case(case_dir: Path, expected_sha: str) -> tuple[str, str]:
    case_name(case_dir.name)
    ensure(case_dir.is_dir() and not case_dir.is_symlink(), "case is not a real directory")
    root_names = {child.name for child in case_dir.iterdir()}
    ensure(root_names in ({"metadata.json", "stdout.bin", "stderr.bin"},
                          {"metadata.json", "stdout.bin", "stderr.bin", "artifacts"}),
           "unexpected or missing case files")
    metadata = case_dir / "metadata.json"
    ensure(not metadata.is_symlink() and metadata.is_file(), "metadata file missing or linked")
    ensure(metadata.stat().st_size <= 64 * 1024, "metadata exceeds 64 KiB")
    try:
        entry = json.loads(metadata.read_text(encoding="utf-8"), object_pairs_hook=unique_pairs)
    except (ValueError, UnicodeError) as exc:
        raise EvidenceError("invalid evidence metadata JSON") from exc
    ensure(isinstance(entry, dict) and set(entry) == EXPECTED_KEYS, "invalid metadata schema")
    ensure(entry["schema"] == SCHEMA and entry["case"] == case_dir.name,
           "case schema or ID mismatch")
    ensure(entry["source_sha"] == expected_sha and entry["head_after"] == expected_sha,
           "source commit mismatch")
    ensure(entry["clean_before"] is True and entry["clean_after"] is True,
           "source tree not clean")
    ensure(entry["host_system"] in {"Linux", "Windows", "Darwin"}, "unrecognized system")
    ensure(type(entry["expected_exit"]) is int and 0 <= entry["expected_exit"] <= 255,
           "invalid expected exit")
    ensure(type(entry["exit_code"]) is int and entry["exit_code"] == entry["expected_exit"],
           "unexpected test exit code")
    ensure(entry["timed_out"] is False, "timed out test cannot qualify")
    ensure(isinstance(entry["command"], list) and entry["command"] and
           all(isinstance(item, str) for item in entry["command"]), "missing command argument evidence")
    ensure(isinstance(entry["files"], dict) and set(entry["files"]) == {"stdout.bin", "stderr.bin"},
           "missing transcript manifest")
    for name in ("stdout.bin", "stderr.bin"):
        check_digest(case_dir / name, entry["files"][name])
    artifacts = entry["artifacts"]
    ensure(isinstance(artifacts, dict) and len(artifacts) <= MAX_FILES,
           "invalid artifact manifest")
    actual = safe_files(case_dir / "artifacts")
    ensure(set(actual) == set(artifacts), "missing or unexpected raw artifacts")
    for relative, path in actual.items():
        check_digest(path, artifacts[relative])
    return case_dir.name, entry["host_system"]


def verify(args: argparse.Namespace) -> None:
    ensure_sha(args.source_sha)
    packet = Path(args.packet)
    ensure(packet.is_dir() and not packet.is_symlink(), "packet is not a real directory")
    observed: dict[str, str] = {}
    cases = sorted(packet.iterdir())
    ensure(bool(cases), "no cases in packet")
    for case in cases:
        name, system = verify_case(case, args.source_sha)
        observed[name] = system
    for requirement in args.require:
        name, sep, system = requirement.partition(":")
        case_name(name)
        ensure(not sep or system in {"Linux", "Windows", "Darwin"}, "invalid required platform")
        ensure(name in observed and (not sep or observed[name] == system),
               "required case or claimed system is absent")
    print(json.dumps({"status": "integrity_valid", "source_sha": args.source_sha,
                      "cases": observed, "independent_review": "not_assessed",
                      "native_platform_attestation": "not_provided"}, sort_keys=True))


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description=__doc__)
    sub = command.add_subparsers(dest="mode", required=True)
    create = sub.add_parser("capture", help="run one explicit command and capture immutable-case bytes")
    create.add_argument("--repo", required=True)
    create.add_argument("--source-sha", required=True)
    create.add_argument("--output", required=True)
    create.add_argument("--case", required=True)
    create.add_argument("--expect-exit", type=int, default=0)
    create.add_argument("--timeout", type=float, default=300)
    create.add_argument("--artifacts", help="copy and hash a command-generated raw artifact directory")
    create.add_argument("command", nargs=argparse.REMAINDER)
    check = sub.add_parser("verify", help="offline check transcript and artifact digests")
    check.add_argument("--packet", required=True)
    check.add_argument("--source-sha", required=True)
    check.add_argument("--require", action="append", default=[], help="case[:Linux|Windows|Darwin]")
    return command


def main() -> int:
    args = parser().parse_args()
    try:
        if args.mode == "capture":
            capture(args)
        else:
            verify(args)
        return 0
    except (EvidenceError, OSError, subprocess.SubprocessError) as exc:
        print(f"E_EVIDENCE: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
