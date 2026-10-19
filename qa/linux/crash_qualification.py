#!/usr/bin/env python3
"""Manual Linux SIGKILL qualification of the *unmodified* OpenScion binary.

Requires Linux, Python 3.10+, C compiler (CC or --cc), and a built dynamically
linked OpenScion CLI. Injects process pauses through a Linux-only LD_PRELOAD
library; the production Rust sources and binaries contain no fault hooks.

This verifies *process termination* and restart behavior, not simulated
electrical power loss, disk firmware write ordering, NTFS, or hostile same-UID
filesystem writers. Never target a production repository.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import hashlib
import json
import os
import pathlib
import platform
import shutil
import signal
import stat
import subprocess
import sys
import time
from typing import Any

POINTS = (
    "blob-before-stage-fsync",
    "blob-after-stage-fsync",
    "blob-before-link",
    "blob-after-link",
    "blob-before-parent-fsync",
    "checkout-before-stage-fsync",
    "checkout-after-publish",
)
POST_BLOB = {"blob-after-link", "blob-before-parent-fsync"}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(args: list[str], name: str, directory: pathlib.Path, *, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, capture_output=True, text=True, timeout=35, check=False)
    (directory / (name + ".stdout")).write_text(result.stdout)
    (directory / (name + ".stderr")).write_text(result.stderr)
    if check and result.returncode != 0:
        raise AssertionError(f"{name}: rc={result.returncode}; stdout={result.stdout!r}; stderr={result.stderr!r}")
    return result


def parse_ok(result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    decoded = json.loads(result.stdout)
    assert result.returncode == 0 and decoded.get("ok") is True, (result.returncode, decoded)
    return decoded


def blob_id(data: bytes) -> str:
    material = b"openscion.blob.v1\x00" + len(data).to_bytes(8, "big") + data
    return "b1_" + sha(material)


def make_repo(binary: str, directory: pathlib.Path, label: str) -> tuple[pathlib.Path, bytes]:
    root = directory / "fixture"
    root.mkdir()
    (root / "src").mkdir()
    content = ("OpenScion forced-crash manual qualification: " + label + "\n").encode()
    (root / "src" / "source.bin").write_bytes(content)
    parse_ok(run([binary, "init", "--json", str(root)], "init", directory))
    return root, content


def inject_and_kill(
    binary: str,
    args: list[str],
    label: str,
    root: pathlib.Path,
    so: pathlib.Path,
    evidence: pathlib.Path,
    *,
    max_wait: float = 10,
) -> dict[str, Any]:
    ready = evidence / "barrier.ready"
    env = os.environ.copy()
    env.update(
        LD_PRELOAD=str(so),
        OPENSCION_TEST_ROOT=str(root),
        OPENSCION_TEST_FAULT_POINT=label,
        OPENSCION_TEST_READY_FILE=str(ready),
    )
    start = time.monotonic()
    with (evidence / "killed.stdout").open("wb") as out, (evidence / "killed.stderr").open("wb") as err:
        child = subprocess.Popen(args, env=env, stdout=out, stderr=err)
        try:
            while not ready.exists():
                if child.poll() is not None:
                    raise AssertionError(f"child exited before fault barrier: {label} rc={child.returncode}")
                if time.monotonic() - start > max_wait:
                    raise AssertionError(f"fault barrier timeout: {label}")
                time.sleep(0.012)
            observed = ready.read_text()
            if observed != label:
                raise AssertionError(f"unexpected barrier: {observed}")
            if child.poll() is not None:
                raise AssertionError(f"child exited at barrier: {label}")
            child.kill()
            returncode = child.wait(timeout=4)
            if returncode != -signal.SIGKILL:
                raise AssertionError(f"expected SIGKILL, observed {returncode}")
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=4)
    return {"point": label, "barrier": ready.read_text(), "terminated_signal": "SIGKILL", "observed_returncode": -signal.SIGKILL, "barrier_latency_ms": round((time.monotonic()-start)*1000, 2)}


def test_blob(
    binary: str, so: pathlib.Path, directory: pathlib.Path, point: str
) -> dict[str, Any]:
    root, data = make_repo(binary, directory, point)
    expected = blob_id(data)
    digest = expected[3:]
    target = root / ".openscion" / "objects" / "b1" / digest[:2] / digest
    record = inject_and_kill(binary, [binary, "blob", "put", "--json", str(root), "src/source.bin"], point, root, so, directory)
    should_exist = point in POST_BLOB
    if target.exists() != should_exist:
        raise AssertionError(f"publication at {point}: expected existence {should_exist}, saw {target.exists()}")
    if should_exist:
        if target.read_bytes() != data:
            raise AssertionError("published blob has noncanonical content")
        parse_ok(run([binary, "blob", "verify", "--json", str(root), expected], "verify-after-crash", directory))
    else:
        missing = run([binary, "blob", "verify", "--json", str(root), expected], "verify-missing", directory, check=False)
        if missing.returncode == 0:
            raise AssertionError("unpublished blob was verified before retry")
    retry = parse_ok(run([binary, "blob", "put", "--json", str(root), "src/source.bin"], "retry", directory))
    if retry["id"] != expected or target.read_bytes() != data:
        raise AssertionError("idempotent retry changed blob identity or bytes")
    parse_ok(run([binary, "blob", "verify", "--json", str(root), expected], "verify-recovered", directory))
    mode = stat.S_IMODE(target.stat().st_mode)
    if mode & 0o077:
        raise AssertionError(f"blob permissions not private: {oct(mode)}")
    orphans = list((root / ".openscion" / "objects").rglob(".openscion-object-*"))
    record.update(
        expected_id=expected,
        final_published_at_pause=should_exist,
        recovered_digest=sha(target.read_bytes()),
        orphan_stages=len(orphans),
        final_mode=oct(mode),
    )
    return record


def test_checkout(
    binary: str, so: pathlib.Path, directory: pathlib.Path, point: str
) -> dict[str, Any]:
    root, data = make_repo(binary, directory, point)
    blob = parse_ok(run([binary, "blob", "put", "--json", str(root), "src/source.bin"], "seed-blob", directory))["id"]
    (root / "manifest.tsv").write_text("src/source.bin\t" + blob + "\t0\n")
    snap = parse_ok(run([binary, "snapshot", "put", "--json", str(root), "manifest.tsv"], "seed-snapshot", directory))["id"]
    destination = root / "materialized"
    command = [binary, "snapshot", "materialize", "--json", str(root), snap, str(destination)]
    record = inject_and_kill(binary, command, point, root, so, directory)
    should_exist = point == "checkout-after-publish"
    if destination.exists() != should_exist:
        raise AssertionError(f"checkout at {point}: expected {should_exist}, got {destination.exists()}")
    if should_exist:
        recovery = run(command, "retry-existing", directory, check=False)
        if recovery.returncode == 0:
            raise AssertionError("already published checkout was overwritten on retry")
        decoded = json.loads(recovery.stdout)
        if decoded.get("code") != "E_ALREADY_EXISTS":
            raise AssertionError(f"unexpected retry denial: {decoded}")
    else:
        parse_ok(run(command, "retry-materialize", directory))
    final = destination / "src" / "source.bin"
    if not final.is_file() or final.read_bytes() != data:
        raise AssertionError("checkout recovery has missing or corrupt file")
    record.update(
        snapshot_id=snap,
        final_published_at_pause=should_exist,
        recovered_digest=sha(final.read_bytes()),
        orphan_stages=len(list(root.glob(".openscion-checkout-*"))),
    )
    return record


def test_races(binary: str, directory: pathlib.Path, contenders: int) -> dict[str, Any]:
    root, data = make_repo(binary, directory, "concurrent-writers")
    expected = blob_id(data)
    with concurrent.futures.ThreadPoolExecutor(max_workers=contenders) as pool:
        attempts = list(pool.map(
            lambda _: subprocess.run(
                [binary, "blob", "put", "--json", str(root), "src/source.bin"],
                capture_output=True, text=True, timeout=35
            ), range(contenders)))
    if any(x.returncode != 0 or json.loads(x.stdout).get("id") != expected for x in attempts):
        raise AssertionError("concurrent identical CAS writes did not converge on one ID")
    parse_ok(run([binary, "blob", "verify", "--json", str(root), expected], "concurrent-verify", directory))
    shard = root / ".openscion" / "objects" / "b1" / expected[3:5]
    published = [p for p in shard.iterdir() if p.name == expected[3:]]
    if len(published) != 1 or published[0].read_bytes() != data:
        raise AssertionError("concurrent blob write corrupted canonical storage")
    (root / "manifest.tsv").write_text("src/source.bin\t" + expected + "\t0\n")
    snapshot = parse_ok(run([binary, "snapshot", "put", "--json", str(root), "manifest.tsv"], "snapshot", directory))["id"]
    command = [binary, "snapshot", "materialize", "--json", str(root), snapshot, str(root / "competing-output")]
    with concurrent.futures.ThreadPoolExecutor(max_workers=contenders) as pool:
        results = list(pool.map(
            lambda _: subprocess.run(command, capture_output=True, text=True, timeout=35),
            range(contenders)))
    winners = sum(x.returncode == 0 for x in results)
    rejects = sum(x.returncode != 0 and json.loads(x.stdout).get("code") == "E_ALREADY_EXISTS" for x in results)
    if winners != 1 or rejects != contenders - 1:
        raise AssertionError(f"racing checkout: successes={winners}, expected already-exists={contenders-1}, saw={rejects}")
    if (root / "competing-output" / "src" / "source.bin").read_bytes() != data:
        raise AssertionError("racing checkouts altered published contents")
    (directory / "race-results.json").write_text(json.dumps(
        {"blob": [{"rc": x.returncode, "stdout": x.stdout.strip()} for x in attempts],
         "checkout": [{"rc": x.returncode, "stdout": x.stdout.strip()} for x in results]},
        indent=2) + "\n")
    return {"contenders": contenders, "identical_blob_writes": contenders,
            "unique_blob_identity": expected, "checkout_winners": winners, "already_exists_rejections": rejects}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=pathlib.Path)
    parser.add_argument("--artifacts", required=True, type=pathlib.Path)
    parser.add_argument("--iterations", type=int, default=3)
    parser.add_argument("--contenders", type=int, default=20)
    parser.add_argument("--cc", default=os.environ.get("CC", "cc"))
    args = parser.parse_args()
    if platform.system() != "Linux":
        parser.error("Linux-only syscall qualification: Windows tests require a native Windows workstation")
    if not 1 <= args.iterations <= 50 or not 2 <= args.contenders <= 64:
        parser.error("iterations must be 1..50 and contenders 2..64")
    binary = args.binary.resolve(strict=True)
    artifacts = args.artifacts.resolve()
    artifacts.mkdir(parents=True, exist_ok=True)
    so = artifacts / "faultshim.so"
    shim = pathlib.Path(__file__).with_name("faultshim.c")
    subprocess.run([args.cc, "-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror", str(shim), "-o", str(so), "-ldl"], check=True)
    try:
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        head = "unavailable"
    report: dict[str, Any] = {
        "protocol": "openscion.qa.linux-process-kill.v1",
        "started_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "git_head": head,
        "binary": str(binary),
        "binary_sha256": sha(binary.read_bytes()),
        "shim_sha256": sha(so.read_bytes()),
        "os": platform.platform(),
        "iterations": args.iterations,
        "cases": [],
        "race": None,
        "qualification_scope": "SIGKILL process isolation, NOT power loss, NOT Windows NTFS",
    }
    failures = []
    for iteration in range(args.iterations):
        for point in POINTS:
            folder = artifacts / f"{iteration+1:02d}-{point}"
            folder.mkdir()
            try:
                case = test_checkout(str(binary), so, folder, point) if point.startswith("checkout") else test_blob(str(binary), so, folder, point)
                case.update(iteration=iteration+1, result="PASS")
            except Exception as e:
                case = {"iteration": iteration+1, "point": point, "result": "FAIL", "error": repr(e)}
                failures.append(case)
            report["cases"].append(case)
            print(f"{case['result']:4} {iteration+1:02d}/{args.iterations:02d} {point}", flush=True)
    race_folder = artifacts / "concurrency"
    race_folder.mkdir()
    try:
        report["race"] = test_races(str(binary), race_folder, args.contenders)
        report["race"]["result"] = "PASS"
    except Exception as e:
        report["race"] = {"result": "FAIL", "error": repr(e)}
        failures.append(report["race"])
    report["finished_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
    report["passed_fault_cases"] = len(report["cases"]) - sum(c["result"] == "FAIL" for c in report["cases"])
    report["failed_fault_cases"] = sum(c["result"] == "FAIL" for c in report["cases"])
    report["raw_artifact_sha256"] = {
        str(file.relative_to(artifacts)): sha(file.read_bytes())
        for file in artifacts.rglob("*")
        if file.is_file() and file.name not in {"summary.json"} and
        "/fixture/" not in str(file)
    }
    (artifacts / "summary.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"head": head, "passed": report["passed_fault_cases"],
                      "failed": report["failed_fault_cases"], "race": report["race"]["result"],
                      "summary": str(artifacts / "summary.json")}, sort_keys=True))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
