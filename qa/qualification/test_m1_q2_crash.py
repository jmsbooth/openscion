"""Tests for fail-closed Windows crash observation setup and evidence shape."""
from __future__ import annotations
import argparse
import importlib.util
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

TARGET = pathlib.Path(__file__).with_name('m1_q2_crash.py')
spec = importlib.util.spec_from_file_location('q2crash', TARGET)
crash = importlib.util.module_from_spec(spec)
spec.loader.exec_module(crash)

class CrashQualificationContract(unittest.TestCase):
    def test_non_windows_must_refuse(self):
        if sys.platform == 'win32':
            self.skipTest('Linux negative test only')
        with self.assertRaisesRegex(crash.Blocked,'NOT_RUN'):
            crash.require_windows_ntfs(pathlib.Path('/tmp'))

    def test_unique_repeatable_payloads(self):
        self.assertEqual(crash.payload(0), crash.payload(0))
        self.assertNotEqual(crash.payload(0), crash.payload(1))
        self.assertEqual(len(crash.payload(16)), crash.BLOB_BYTES)

    def test_explicit_coverage_boundaries(self):
        src = TARGET.read_text(encoding='utf-8')
        self.assertIn('"boundary_injection": False', src)
        self.assertIn('"power_loss_verified": False', src)
        self.assertIn('"independent_security_review": "not_obtained"', src)

    def test_shalength_and_worktree(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp)
            for cmd in (["git", "init", "-q"],
                        ["git", "config", "user.email", "qa@example.invalid"],
                        ["git", "config", "user.name", "QA"]):
                subprocess.run(cmd, cwd=path, check=True)
            (path / 'file').write_text('ok')
            subprocess.run(['git', 'add', 'file'], cwd=path, check=True)
            subprocess.run(['git','commit','-qm','test'],cwd=path,check=True)
            sha=subprocess.run(['git','rev-parse','HEAD'],cwd=path,check=True,capture_output=True,text=True).stdout.strip()
            crash.strict_head(path, sha)
            with self.assertRaisesRegex(crash.Blocked,'source SHA'):
                crash.strict_head(path, 'a' * 39)
            (path / 'file').write_text('dirty')
            with self.assertRaisesRegex(crash.Blocked,'dirty'):
                crash.strict_head(path, sha)

    def test_existing_evidence_never_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp)
            repo=root/'repo';repo.mkdir()
            binary=root/'app.exe';binary.write_bytes(b'placeholder')
            existing=root/'raw';existing.mkdir()
            args=argparse.Namespace(repo=str(repo),binary=str(binary),expected_sha='a'*40,artifacts=str(existing),fixture=str(root/'fixture'),attempts=10)
            with self.assertRaisesRegex(crash.Blocked,'refusing to overwrite'):
                crash.preflight(args)

    def test_bad_attempt_limit_fails_before_host_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp)
            repo=root/'repo';repo.mkdir()
            binary=root/'app.exe';binary.write_bytes(b'placeholder')
            args=argparse.Namespace(repo=str(repo),binary=str(binary),expected_sha='a'*40,artifacts=str(root/'raw'),fixture=str(root/'fixture'),attempts=129)
            with self.assertRaisesRegex(crash.Blocked,'out of bounds'):
                crash.preflight(args)

    def test_refuse_symlinked_evidence_ancestor(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp)
            destination=root/'original';destination.mkdir()
            link=root/'linked'
            try:
                link.symlink_to(destination, target_is_directory=True)
            except (OSError,NotImplementedError):
                self.skipTest('symlink creation unavailable')
            with self.assertRaisesRegex(crash.Blocked,'reparse point'):
                crash.reject_linked_ancestors(link / 'artifact')

    def test_observational_subprocess_recovery_on_fake_cli(self):
        # Tests the harness state machine, NOT Win32 or production OpenScion.
        if sys.platform == 'win32':
            self.skipTest('POSIX fake CLI exercise only')
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp)
            repo=root/'checkout';repo.mkdir()
            for cmd in (["git", "init", "-q"],
                        ["git", "config", "user.email", "qa@example.invalid"],
                        ["git", "config", "user.name", "QA"]):
                subprocess.run(cmd, cwd=repo, check=True)
            (repo/'.gitignore').write_text('target/\n')
            subprocess.run(['git','add','.gitignore'],cwd=repo,check=True)
            subprocess.run(['git','commit','-qm','fixture'],cwd=repo,check=True)
            sha=subprocess.run(['git','rev-parse','HEAD'],cwd=repo,check=True,capture_output=True,text=True).stdout.strip()
            binary=repo/'target/debug/openscion.exe';binary.parent.mkdir(parents=True)
            fake="""#!/usr/bin/env python3
import hashlib,json,sys,time
from pathlib import Path
args=sys.argv[1:]
if args[0]=='init':
    (Path(args[-1])/'.openscion').mkdir()
    print(json.dumps({'ok':True,'command':'init'}))
elif args[:2]==['blob','put']:
    repo=Path(args[-2]);data=(repo/args[-1]).read_bytes()
    time.sleep(0.020)
    id='b1_'+hashlib.sha256(data).hexdigest()
    (repo/'.openscion'/id).write_bytes(data)
    print(json.dumps({'ok':True,'command':'blob put','id':id}))
elif args[:2]==['blob','verify']:
    repo=Path(args[-2]);id=args[-1]
    data=(repo/'.openscion'/id).read_bytes()
    assert hashlib.sha256(data).hexdigest()==id[3:]
    print(json.dumps({'ok':True,'command':'blob verify','id':id,'bytes':len(data)}))
else:
    sys.exit(2)
"""
            binary.write_text(fake)
            binary.chmod(0o755)
            args=SimpleNamespace(expected_sha=sha,attempts=8)
            with mock.patch.object(crash,'preflight',return_value=(repo,binary,root/'evidence',root/'fixture')):
                result=crash.run(args)
            self.assertEqual(result['attempts'],8)
            self.assertGreater(result['interrupted_count'],0)
            self.assertFalse(result['boundary_injection'])
            self.assertFalse(result['power_loss_verified'])
            self.assertTrue(all(o['retry_verified'] for o in result['observations']))
            self.assertTrue((root/'evidence'/'summary.json').exists())

    def test_oversized_native_command_output_is_rejected(self):
        with self.assertRaisesRegex(crash.Blocked,'oversized response'):
            crash.execute(pathlib.Path(sys.executable),
                          ['-c', "import sys;sys.stdout.write('X'*131073)"])

    def test_full_cli_argv_has_no_shell(self):
        src=TARGET.read_text(encoding='utf-8')
        self.assertIn('subprocess.Popen([str(binary), "blob", "put", "--json",',src)
        self.assertNotIn('shell=True',src)

if __name__=='__main__': unittest.main()
