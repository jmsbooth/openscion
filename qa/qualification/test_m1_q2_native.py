"""Tests that M1-Q2 orchestration fails closed unless native prerequisites exist."""
from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest import mock

TARGET = Path(__file__).with_name("m1_q2_native.py")
spec = importlib.util.spec_from_file_location("native_gate", TARGET)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class M1Q2Contract(unittest.TestCase):
    def test_non_windows_host_denied(self):
        if sys.platform == "win32":
            self.skipTest("this is a Linux-side negative test")
        with self.assertRaisesRegex(RuntimeError, "NOT_RUN"):
            gate.require_native_ntfs(Path("/tmp"))

    def test_wrong_sha_rejected_before_any_host_tests(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run([sys.executable, str(TARGET),
                                     "--repo", tmp, "--output", str(Path(tmp).parent / "unused-packet"),
                                     "--expected-sha", "wrong", "--suite", "revision"],
                                    capture_output=True, text=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("E_M1_Q2_BLOCKED", result.stderr)

    def test_supported_suites_have_exact_nonredundant_case_names(self):
        names = [name for name, _ in gate.CHECKS]
        self.assertEqual(len(names), len(set(names)))
        self.assertIn("rust-tests", names)
        self.assertIn("rust-build", names)
        self.assertIn("rust-clippy", names)

    def test_refuse_existing_evidence_path_before_host_test(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            packet = root / "packet"
            packet.mkdir()
            result = subprocess.run([sys.executable, str(TARGET),
                                     "--repo", str(root), "--output", str(packet),
                                     "--expected-sha", "a" * 40, "--suite", "cli"],
                                    capture_output=True, text=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("new packet path", result.stderr)

    def test_native_host_check_must_precede_external_commands(self):
        if sys.platform == "win32":
            self.skipTest("platform-specific test")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "source"
            repo.mkdir()
            output = root / "new-packet"
            with mock.patch.object(gate, "require_native_ntfs", side_effect=RuntimeError("NOT_RUN: no host")) as check:
                ns = type("NS", (), dict(repo=str(repo), expected_sha="a" * 40,
                                         output=str(output), suite="cli"))()
                with self.assertRaisesRegex(RuntimeError, "NOT_RUN"):
                    gate.run(ns)
                check.assert_called_once()
            self.assertFalse(output.exists())

    def test_exact_commit_and_clean_worktree_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            for command in (["git", "init", "-q"],
                            ["git", "config", "user.email", "qa@example.invalid"],
                            ["git", "config", "user.name", "QA"]):
                subprocess.run(command, cwd=repo, check=True)
            (repo / "Cargo.toml").write_text("[workspace]\n", encoding="utf-8")
            subprocess.run(["git", "add", "Cargo.toml"], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-qm", "fixture"], cwd=repo, check=True)
            head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo,
                                  capture_output=True, text=True, check=True).stdout.strip()
            output = root / "packet"
            ns = type("NS", (), dict(repo=str(repo), expected_sha="a" * 40,
                                     output=str(output), suite="cli"))()
            with mock.patch.object(gate, "require_native_ntfs"):
                with mock.patch.object(gate, "HELPER", TARGET):
                    with self.assertRaisesRegex(RuntimeError, "wrong Git source head"):
                        gate.run(ns)
                    ns.expected_sha = head
                    (repo / "Cargo.toml").write_text("[workspace]\n# dirty\n", encoding="utf-8")
                    with self.assertRaisesRegex(RuntimeError, "dirty checkout"):
                        gate.run(ns)
            self.assertFalse(output.exists())

    def test_no_release_approval_string_in_success(self):
        source = TARGET.read_text(encoding="utf-8")
        self.assertIn("independent security signoff still required", source)
        self.assertNotIn("security_approved", source)


if __name__ == "__main__":
    unittest.main()
