"""Verify portable evidence against real captures and damaged artifacts."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "export-stack-canary.py"


@unittest.skipUnless(all(shutil.which(tool) for tool in
                        ("gcc", "make", "readelf", "objdump", "getconf")), "requires Linux build tools")
class EvidenceExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="export evidence ")
        cls.addClassCleanup(cls.directory.cleanup)
        cls.capture = Path(cls.directory.name) / "original"
        env = {key: value for key, value in os.environ.items()
               if key not in ("CC", "CFLAGS", "LDFLAGS")}
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/capture-stack-canary.py"), "host", str(cls.capture)],
            env=env, capture_output=True, text=True, timeout=90)
        if result.returncode:
            raise RuntimeError(result.stderr)

    def run_export(self, output, *captures):
        return subprocess.run([sys.executable, str(SCRIPT), *map(str, captures or (self.capture,)),
                               "--output", str(output)], capture_output=True, text=True, timeout=10)

    def test_exports_all_observations_and_original_manifest_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "evidence.json"
            result = self.run_export(output)
            self.assertEqual(result.returncode, 0, result.stderr)
            capture = json.loads(output.read_text())["captures"][0]
            self.assertEqual(capture["full_manifest_sha256"],
                             hashlib.sha256((self.capture / "SHA256SUMS").read_bytes()).hexdigest())
            self.assertEqual(len(capture["observations"]), 18)
            for row in capture["observations"]:
                stem = "{binary}.{mode}.{repeat}".format(**row)
                for stream in ("stdout", "stderr"):
                    self.assertEqual(row[stream], (self.capture / "04-stack-canary" /
                                                  (stem + "." + stream + ".txt")).read_text())

    def test_rejects_incomplete_tampered_extra_and_unsafe_artifacts(self):
        for case in ("incomplete", "tampered", "extra", "symlink", "traversal", "duplicate"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                capture = root / "capture"
                shutil.copytree(self.capture, capture)
                manifest = capture / "SHA256SUMS"
                if case == "incomplete":
                    (capture / "COMPLETE").unlink()
                elif case == "tampered":
                    (capture / "04-stack-canary/stack_canary.overflow.1.stderr.txt").write_text("changed")
                elif case == "extra":
                    (capture / "untracked").touch()
                elif case == "symlink":
                    (capture / "external").symlink_to(self.capture, target_is_directory=True)
                elif case == "traversal":
                    manifest.write_text("0" * 64 + "  ../outside\n")
                else:
                    manifest.write_text(manifest.read_text() * 2)
                output = root / "evidence.json"
                self.assertNotEqual(self.run_export(output, capture).returncode, 0)
                self.assertFalse(output.exists())

    def test_preserves_existing_output_and_rejects_duplicate_capture_names(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "evidence.json"
            output.write_text("keep")
            self.assertNotEqual(self.run_export(output).returncode, 0)
            self.assertEqual(output.read_text(), "keep")
            link = root / "link.json"
            link.symlink_to(root / "missing")
            self.assertNotEqual(self.run_export(link).returncode, 0)
            self.assertTrue(link.is_symlink())
            self.assertFalse((root / "missing").exists())
            fresh = root / "new.json"
            self.assertNotEqual(self.run_export(fresh, self.capture, self.capture).returncode, 0)
            self.assertFalse(fresh.exists())
