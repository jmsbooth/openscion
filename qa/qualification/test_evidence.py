"""Contract tests for an integrity-only, manually run qualification packet."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("evidence.py")


class EvidenceContract(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.repo = base / "repository"
        self.repo.mkdir()
        self.packet = base / "packet"
        self.packet.mkdir()
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Test Runner")
        (self.repo / "README.md").write_text("fixture\n", encoding="utf-8")
        self.git("add", "README.md")
        self.git("commit", "-qm", "fixture")
        self.head = self.git("rev-parse", "HEAD").stdout.strip()

    def git(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["git", *args], cwd=self.repo, text=True,
                              capture_output=True, check=True)

    def cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([sys.executable, str(SCRIPT), *args],
                              text=True, capture_output=True)

    def capture(self, case: str, code: str, *options: str) -> subprocess.CompletedProcess[str]:
        return self.cli("capture", "--repo", str(self.repo),
                        "--source-sha", self.head, "--output", str(self.packet / case),
                        "--case", case, *options, "--", sys.executable, "-c", code)

    def verify(self, *options: str) -> subprocess.CompletedProcess[str]:
        return self.cli("verify", "--packet", str(self.packet),
                        "--source-sha", self.head, *options)

    def test_capture_verify_exact_head_and_both_streams(self) -> None:
        completed = self.capture("linux-check", "import sys;print('out');print('err',file=sys.stderr)")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        validated = self.verify("--require", f"linux-check:{platform.system()}")
        self.assertEqual(validated.returncode, 0, validated.stderr)
        entry = json.loads((self.packet / "linux-check" / "metadata.json").read_text())
        self.assertEqual(entry["source_sha"], self.head)
        self.assertEqual(entry["host_system"], platform.system())
        self.assertEqual(entry["expected_exit"], 0)
        self.assertEqual(entry["exit_code"], 0)
        self.assertEqual((self.packet / "linux-check" / "stdout.bin").read_bytes(), b"out\n")
        self.assertEqual((self.packet / "linux-check" / "stderr.bin").read_bytes(), b"err\n")

    def test_nonzero_expected_exit_is_valid_negative_evidence(self) -> None:
        self.assertEqual(self.capture("deny-traversal", "import sys;sys.exit(7)",
                                      "--expect-exit", "7").returncode, 0)
        self.assertEqual(self.verify("--require", "deny-traversal").returncode, 0)

    def test_unexpected_exit_fails_but_retains_raw_logs(self) -> None:
        done = self.capture("must-fail", "import sys;sys.exit(3)")
        self.assertNotEqual(done.returncode, 0)
        self.assertTrue((self.packet / "must-fail" / "metadata.json").is_file())
        self.assertNotEqual(self.verify().returncode, 0)

    def test_wrong_source_sha_refuses_before_execution(self) -> None:
        marker = self.packet / "ran"
        done = self.cli("capture", "--repo", str(self.repo),
                        "--source-sha", "0" * 40, "--output", str(self.packet / "wrong"),
                        "--case", "wrong", "--", sys.executable, "-c",
                        f"from pathlib import Path;Path({str(marker)!r}).touch()")
        self.assertNotEqual(done.returncode, 0)
        self.assertFalse(marker.exists())
        self.assertFalse((self.packet / "wrong").exists())

    def test_dirty_repo_refuses_execution(self) -> None:
        (self.repo / "README.md").write_text("dirty\n")
        result = self.capture("dirty", "print('never')")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.packet / "dirty").exists())

    def test_duplicate_case_cannot_overwrite_packet(self) -> None:
        self.assertEqual(self.capture("once", "print('first')").returncode, 0)
        self.assertNotEqual(self.capture("once", "print('second')").returncode, 0)
        self.assertEqual((self.packet / "once" / "stdout.bin").read_bytes(), b"first\n")

    def test_mutated_log_rejected(self) -> None:
        self.assertEqual(self.capture("tamper", "print('original')").returncode, 0)
        with (self.packet / "tamper" / "stdout.bin").open("ab") as out:
            out.write(b"altered")
        self.assertNotEqual(self.verify().returncode, 0)

    def test_malformed_and_duplicate_metadata_keys_rejected(self) -> None:
        self.assertEqual(self.capture("duplicate", "print('ok')").returncode, 0)
        path = self.packet / "duplicate" / "metadata.json"
        original = path.read_text()
        self.assertTrue(original.startswith("{"))
        path.write_text('{"schema":"a","schema":"b"}', encoding="utf-8")
        self.assertNotEqual(self.verify().returncode, 0)

    def test_missing_required_case_or_mismatched_platform_rejected(self) -> None:
        self.assertEqual(self.capture("linux-check", "print('ok')").returncode, 0)
        self.assertNotEqual(self.verify("--require", "missing:Windows").returncode, 0)
        other = "Windows" if platform.system() != "Windows" else "Linux"
        self.assertNotEqual(self.verify("--require", f"linux-check:{other}").returncode, 0)

    def test_invalid_case_id_rejected_without_execution(self) -> None:
        done = self.capture("../invalid", "print('never')")
        self.assertNotEqual(done.returncode, 0)

    def test_symlinked_log_or_extra_packet_file_rejected(self) -> None:
        self.assertEqual(self.capture("safe", "print('ok')").returncode, 0)
        original = self.packet / "safe" / "stdout.bin"
        original.unlink()
        target = self.packet / "target"
        target.write_bytes(b"ok\n")
        try:
            original.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable on this host")
        self.assertNotEqual(self.verify().returncode, 0)

    def test_binary_attachment_copy_and_hash_detect_mutation(self) -> None:
        source = Path(self.tmp.name) / "raw"
        (source / "nested").mkdir(parents=True)
        binary = b"\x00\xff\x01\x02"
        (source / "nested" / "log.dat").write_bytes(binary)
        self.assertEqual(self.capture("archive", "print('ok')", "--artifacts", str(source)).returncode, 0)
        copied = self.packet / "archive" / "artifacts" / "nested" / "log.dat"
        self.assertEqual(copied.read_bytes(), binary)
        self.assertEqual(self.verify().returncode, 0)
        copied.write_bytes(binary + b"X")
        self.assertNotEqual(self.verify().returncode, 0)

    def test_artifact_symlink_refused(self) -> None:
        source = Path(self.tmp.name) / "raw"
        source.mkdir()
        target = Path(self.tmp.name) / "secret"
        target.write_text("private")
        try:
            (source / "secret-link").symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable on this host")
        self.assertNotEqual(self.capture("bad-artifact", "print('ok')", "--artifacts", str(source)).returncode, 0)
        self.assertNotEqual(self.verify().returncode, 0)

    def test_missing_artifact_directory_is_not_a_pass(self) -> None:
        absent = Path(self.tmp.name) / "missing"
        done = self.capture("missing-raw", "print('ok')", "--artifacts", str(absent))
        self.assertNotEqual(done.returncode, 0)
        self.assertNotEqual(self.verify().returncode, 0)

    def test_capture_timeout_is_retained_but_not_accepted(self) -> None:
        completed = self.capture("timeout", "import time;time.sleep(4)",
                                 "--timeout", "0.05")
        self.assertNotEqual(completed.returncode, 0)
        entry = json.loads((self.packet / "timeout" / "metadata.json").read_text())
        self.assertTrue(entry["timed_out"])
        self.assertNotEqual(self.verify().returncode, 0)

    def test_source_sha_and_packet_location_must_be_safe(self) -> None:
        self.assertEqual(self.capture("normal", "print('ok')").returncode, 0)
        self.assertNotEqual(self.verify("--source-sha", "f" * 40).returncode, 0)
        output_in_repo = self.repo / "in-repo"
        completed = self.cli("capture", "--repo", str(self.repo),
                             "--source-sha", self.head, "--output", str(output_in_repo),
                             "--case", "in-repo", "--", sys.executable, "-c", "print(1)")
        self.assertNotEqual(completed.returncode, 0)
        self.assertFalse(output_in_repo.exists())

    def test_no_synthetic_reviewer_approval_in_verification_result(self) -> None:
        self.assertEqual(self.capture("check", "print('pass')").returncode, 0)
        verified = self.verify()
        self.assertEqual(verified.returncode, 0, verified.stderr)
        report = json.loads(verified.stdout)
        self.assertEqual(report["status"], "integrity_valid")
        self.assertEqual(report["independent_review"], "not_assessed")
        self.assertEqual(report["native_platform_attestation"], "not_provided")


if __name__ == "__main__":
    unittest.main()
