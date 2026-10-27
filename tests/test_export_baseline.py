"""Export real baseline captures and reject damaged or mismatched evidence."""
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
SCRIPT = ROOT / "scripts/export-baseline.py"


class RecordedEvidenceTests(unittest.TestCase):
    def test_recorded_comparison_and_session_text_match_their_hashes(self):
        evidence = ROOT / "docs/evidence"
        data = json.loads((evidence / "baseline-comparison-2026-10-27.json").read_text())
        self.assertEqual({item["label"] for item in data["captures"]}, {"legacy", "modern"})
        self.assertEqual(len(data["captures"]), 2)
        for capture in data["captures"]:
            self.assertEqual(len([name for name in capture["files"] if ".run-" in name]), 15)
            for name, content in capture["files"].items():
                if name in capture["artifact_sha256"]:
                    self.assertEqual(hashlib.sha256(content.encode()).hexdigest(),
                                     capture["artifact_sha256"][name], name)
            self.assertEqual(hashlib.sha256(capture["files"]["SHA256SUMS"].encode()).hexdigest(),
                             capture["full_manifest_sha256"])
            for name, value in data["matching_inputs"]["artifact_sha256"].items():
                self.assertEqual(capture["artifact_sha256"][name], value)
            self.assertEqual(capture["build_variables"], data["matching_inputs"]["build_variables"])
        session = json.loads((evidence / "modern-session-2026-10-27.json").read_text())
        for name, content in session["guest_text_artifacts"].items():
            self.assertEqual(hashlib.sha256(content.encode()).hexdigest(), session["artifact_sha256"][name])
        self.assertEqual(session["source_image_sha256_before"], session["source_image_sha256_after"])


@unittest.skipUnless(all(shutil.which(tool) for tool in ("gcc", "make", "readelf", "objdump")),
                     "requires host compiler and binutils")
class BaselineExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="baseline export ")
        cls.addClassCleanup(cls.directory.cleanup)
        cls.capture = Path(cls.directory.name) / "host-original"
        env = {key: value for key, value in os.environ.items()
               if key not in ("CC", "CFLAGS", "LDFLAGS")}
        result = subprocess.run(["bash", str(ROOT / "scripts/capture-baseline.sh"),
                                 "host", str(cls.capture)], env=env, capture_output=True,
                                text=True, timeout=60)
        if result.returncode:
            raise RuntimeError(result.stderr)

    def run_export(self, output, *captures):
        return subprocess.run([sys.executable, str(SCRIPT), *map(str, captures or (self.capture,)),
                               "--output", str(output)], capture_output=True, text=True, timeout=20)

    def test_exports_matching_captures_and_all_runtime_transcripts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            second = root / "host-replica"
            shutil.copytree(self.capture, second)
            output = root / "evidence.json"
            result = self.run_export(output, self.capture, second)
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(output.read_text())
            self.assertEqual(data["schema_version"], 1)
            self.assertEqual(len(data["captures"]), 2)
            for capture in data["captures"]:
                self.assertTrue(capture["label_is_operator_supplied"])
                self.assertEqual(capture["label"], "host")
                self.assertEqual(len([name for name in capture["files"] if ".run-" in name]), 15)
                self.assertFalse(any(name.endswith(".disassembly.txt") for name in capture["files"]))
                for name, content in capture["files"].items():
                    self.assertEqual(content, (self.capture / name).read_text())
                for name, value in capture["artifact_sha256"].items():
                    self.assertEqual(value, hashlib.sha256((self.capture / name).read_bytes()).hexdigest())

    def test_rejects_incomplete_tampered_extra_symlink_and_unsafe_manifest(self):
        for case in ("incomplete", "tampered", "extra", "symlink", "traversal", "duplicate"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                capture = root / "capture"
                shutil.copytree(self.capture, capture)
                manifest = capture / "SHA256SUMS"
                if case == "incomplete":
                    (capture / "COMPLETE").unlink()
                elif case == "tampered":
                    (capture / "01-process-memory-layout/memory_layout.run-1.txt").write_text("changed")
                elif case == "extra":
                    (capture / "untracked.txt").touch()
                elif case == "symlink":
                    (capture / "external").symlink_to(self.capture, target_is_directory=True)
                elif case == "traversal":
                    manifest.write_text("0" * 64 + "  ../outside\n")
                else:
                    manifest.write_text(manifest.read_text() * 2)
                output = root / "evidence.json"
                self.assertNotEqual(self.run_export(output, capture).returncode, 0)
                self.assertFalse(output.exists())

    def test_rejects_different_inputs_even_with_consistent_checksums(self):
        for case in ("source", "flags"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                capture = root / "different"
                shutil.copytree(self.capture, capture)
                if case == "source":
                    path = capture / "01-process-memory-layout/src/memory_layout.c"
                    path.write_text(path.read_text() + "\n/* Changed experiment. */\n")
                else:
                    path = capture / "environment.txt"
                    path.write_text(path.read_text().replace("CFLAGS=-O0", "CFLAGS=-O2"))
                # Rehash leaf manifests before the root manifest: integrity alone
                # must not be mistaken for matched experimental inputs.
                for manifest in [*sorted(capture.glob("*/SHA256SUMS")), capture / "SHA256SUMS"]:
                    lines = []
                    for line in manifest.read_text().splitlines():
                        _, name = line.split("  ", 1)
                        lines.append(hashlib.sha256((manifest.parent / name).read_bytes()).hexdigest()
                                     + "  " + name)
                    manifest.write_text("\n".join(lines) + "\n")
                # A standalone snapshot is valid; pairing with a different
                # experiment is rejected before any output is written.
                self.assertEqual(self.run_export(root / "single.json", capture).returncode, 0)
                result = self.run_export(root / "pair.json", self.capture, capture)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("comparison inputs differ", result.stderr)
                self.assertFalse((root / "pair.json").exists())

    def test_preserves_existing_output_and_rejects_duplicate_capture_names(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "existing.json"
            output.write_text("keep")
            self.assertNotEqual(self.run_export(output).returncode, 0)
            self.assertEqual(output.read_text(), "keep")
            link = root / "link.json"
            link.symlink_to(root / "missing")
            self.assertNotEqual(self.run_export(link).returncode, 0)
            self.assertTrue(link.is_symlink())
            self.assertFalse((root / "missing").exists())
            fresh = root / "fresh.json"
            self.assertNotEqual(self.run_export(fresh, self.capture, self.capture).returncode, 0)
            self.assertFalse(fresh.exists())
