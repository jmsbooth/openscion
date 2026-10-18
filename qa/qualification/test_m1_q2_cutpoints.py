"""Fail-closed FOSS-491 controller contracts; NOT native Windows acceptance."""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

FILE = Path(__file__).with_name("m1_q2_cutpoints.py")
SPEC = importlib.util.spec_from_file_location("cutpoints", FILE)
controller = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(controller)


class CutpointContracts(unittest.TestCase):
    def test_no_linux_host_qualifies_as_windows(self):
        if sys.platform == "win32":
            self.skipTest("Linux-only negative")
        with self.assertRaisesRegex(controller.QualificationError, "NOT_RUN"):
            controller.native_ntfs(Path("/tmp"))

    def test_point_table_is_unique_and_covers_every_release_boundary(self):
        self.assertEqual(len(controller.POINTS), 12)
        self.assertTrue(all(point.startswith(("object_", "checkout_")) for point in controller.POINTS))
        self.assertFalse(controller.POINTS["object_before_publish"])
        self.assertTrue(controller.POINTS["object_after_publish"])
        self.assertFalse(controller.POINTS["checkout_before_publish"])
        self.assertTrue(controller.POINTS["checkout_after_publish"])

    def test_bad_nonce_and_point_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(controller.QualificationError):
                controller.marker_path(Path(tmp), "x" * 32, "bad-point")
            with self.assertRaises(controller.QualificationError):
                controller.marker_path(Path(tmp), "../../", "object_before_publish")

    def test_receipt_must_match_exact_pid_nonce_and_point(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            nonce = "a" * 32
            point = "object_before_publish"
            path = controller.marker_path(parent, nonce, point)
            path.write_text(f"v1\npoint={point}\nnonce={nonce}\npid=42\n")
            self.assertEqual(len(controller.validate_marker(path, point, nonce, 42)), 64)
            with self.assertRaisesRegex(controller.QualificationError, "does not match"):
                controller.validate_marker(path, point, nonce, 43)
            path.write_text(f"v1\npoint={point}\nnonce={nonce}\npid=42\nforged=1\n")
            with self.assertRaises(controller.QualificationError):
                controller.validate_marker(path, point, nonce, 42)

    def test_symlinked_marker_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            nonce = "b" * 32
            point = "object_after_publish"
            path = controller.marker_path(parent, nonce, point)
            original = parent / "event"
            original.write_text(f"v1\npoint={point}\nnonce={nonce}\npid=12\n")
            try:
                path.symlink_to(original)
            except (NotImplementedError, OSError):
                self.skipTest("symlinks unavailable")
            with self.assertRaisesRegex(controller.QualificationError, "linked"):
                controller.validate_marker(path, point, nonce, 12)

    def test_existing_evidence_and_wrong_sha_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaisesRegex(controller.QualificationError, "40-hex"):
                controller.source_state(root, "ABC")
            repo = root / "repo"
            repo.mkdir()
            fixture = root / "packet"
            fixture.mkdir()
            args = argparse.Namespace(repo=str(repo), binary=str(repo), evidence=str(fixture),
                                      expected_sha="a" * 40, timeout=15)
            with self.assertRaisesRegex(controller.QualificationError, "fresh path"):
                controller.preflight(args)

    def test_refuse_linked_evidence_ancestor(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root = parent / "real"
            root.mkdir()
            link = parent / "alias"
            try:
                link.symlink_to(root, target_is_directory=True)
            except (NotImplementedError, OSError):
                self.skipTest("symlinks unavailable")
            with self.assertRaisesRegex(controller.QualificationError, "symlink"):
                controller.ensure_nolinks(link / "packet")

    def test_cleared_env_does_not_inherit_faultpoint(self):
        with mock.patch.dict(controller.os.environ,
                             {"OPENSCION_QA_CUTPOINT": "object_after_publish",
                              "OPENSCION_QA_MARKER_DIR": "/bad", "OPENSCION_QA_NONCE": "fake"}):
            env = controller.clean_environment()
            for key in controller.ENV_KEYS:
                self.assertNotIn(key, env)

    def test_unreached_cutpoint_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            fake = parent / "exit.exe"
            fake.write_text(f"#!{sys.executable}\nimport sys;sys.exit(12)\n")
            fake.chmod(0o755)
            result_dir = parent / "logs"
            result_dir.mkdir()
            with self.assertRaisesRegex(controller.QualificationError, "without reaching"):
                controller.controlled_kill(fake, [], result_dir, "object_before_publish", "c" * 32, 2)

    def test_fake_cli_exact_cutpoint_then_process_kill_retry(self):
        # POSIX fake intentionally tests controller plumbing only; not real CAS.
        if sys.platform == "win32":
            self.skipTest("POSIX fake binary")
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            repo = base / "repo"
            repo.mkdir()
            for cmd in (["git", "init", "-q"], ["git", "config", "user.name", "Test"],
                        ["git", "config", "user.email", "qa@example.invalid"]):
                subprocess.run(cmd, cwd=repo, check=True)
            (repo / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")
            (repo / ".gitignore").write_text("target/\n", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-qm", "fixture"], cwd=repo, check=True)
            head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, check=True,
                                  capture_output=True, text=True).stdout.strip()
            binary = repo / "target/debug/openscion.exe"
            binary.parent.mkdir(parents=True)
            binary.write_text(textwrap.dedent('''\
                #!PYTHON
                import hashlib,json,os,sys,time
                from pathlib import Path
                args=sys.argv[1:];env=os.environ
                def out(command,**extra):
                    print(json.dumps(dict(ok=True,command=command,**extra)))
                def point(at):
                    requested=env.get('OPENSCION_QA_CUTPOINT')
                    if at!=requested: return
                    directory=Path(env['OPENSCION_QA_MARKER_DIR'])
                    nonce=env['OPENSCION_QA_NONCE']
                    marker=directory/(nonce+'.'+at+'.hit')
                    marker.write_text(f'v1\\npoint={at}\\nnonce={nonce}\\npid={os.getpid()}\\n')
                    while True: time.sleep(0.1)
                if args[0]=='init':
                    (Path(args[-1])/'.openscion').mkdir()
                    out('init')
                elif args[:2]==['blob','put']:
                    root=Path(args[-2]);data=(root/args[-1]).read_bytes()
                    ident='b1_'+hashlib.sha256(data).hexdigest();d=ident[3:]
                    target=root/'.openscion'/'objects'/'b1'/d[:2]/d
                    target.parent.mkdir(parents=True,exist_ok=True)
                    for name in ('object_before_stage_fsync','object_after_stage_fsync','object_before_publish'):point(name)
                    target.write_bytes(data)
                    for name in ('object_after_publish','object_before_stage_remove',
                                 'object_after_stage_remove','object_before_parent_sync',
                                 'object_after_parent_sync'):point(name)
                    out('blob put',id=ident)
                elif args[:2]==['blob','verify']:
                    root=Path(args[-2]);ident=args[-1];d=ident[3:]
                    data=(root/'.openscion'/'objects'/'b1'/d[:2]/d).read_bytes()
                    assert 'b1_'+hashlib.sha256(data).hexdigest()==ident
                    out('blob verify',id=ident,bytes=len(data))
                elif args[:2]==['snapshot','put']:
                    root=Path(args[-2]);data=(root/args[-1]).read_bytes()
                    out('snapshot put',id='s1_'+hashlib.sha256(data).hexdigest())
                elif args[:2]==['snapshot','materialize']:
                    root=Path(args[-3]); target=Path(args[-1]); target.parent.mkdir(exist_ok=True)
                    if target.exists():
                        print(json.dumps({'ok':False,'code':'E_ALREADY_EXISTS'}));sys.exit(5)
                    point('checkout_before_publish')
                    target.mkdir(); (target/'source.bin').write_bytes((root/'source.bin').read_bytes())
                    for name in ('checkout_after_publish','checkout_before_parent_sync',
                                 'checkout_after_parent_sync'):point(name)
                    out('snapshot materialize')
                else: sys.exit(2)
                '''.replace('PYTHON', sys.executable)))
            binary.chmod(0o755)
            output = base / "evidence"
            args = argparse.Namespace(repo=str(repo), binary=str(binary), evidence=str(output),
                                      expected_sha=head, timeout=5)
            # Exercise representative pre/post object + checkout edges;
            # the full 12-case table remains an on-host release requirement.
            selected = {k: controller.POINTS[k] for k in (
                "object_before_publish", "object_after_publish",
                "checkout_before_publish", "checkout_after_publish")}
            with mock.patch.object(controller, "native_ntfs"), mock.patch.dict(controller.POINTS, selected, clear=True):
                result = controller.run(args)
            self.assertEqual(result["status"], "observed")
            self.assertEqual(result["completed_count"], 4)
            self.assertFalse(result["physical_power_loss_verified"])
            self.assertEqual(result["independent_review"], "not_obtained")
            self.assertEqual(len([o for o in result["observations"] if o["checkpoint_observed"]]), 4)
            self.assertTrue((output / "summary.json").is_file())


if __name__ == "__main__":
    unittest.main()
