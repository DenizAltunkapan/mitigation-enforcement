"""Real compiler and runtime checks for Lab 07 (runtime execution permission)."""
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
SCRIPT = ROOT / "scripts" / "capture-wx.py"
EXPORTER = ROOT / "scripts" / "export-wx.py"
TOOLS = ("gcc", "make", "readelf", "objdump", "getconf")


def capture(output, flags=None, label="host"):
    env = os.environ.copy()
    for key in ("CC", "CFLAGS", "LDFLAGS"):
        env.pop(key, None)
    if flags is not None:
        env["CFLAGS"] = flags
    return subprocess.run(
        [sys.executable, "-O", str(SCRIPT), label, str(output)],
        cwd="/tmp", env=env, capture_output=True, timeout=90,
    )


@unittest.skipUnless(all(shutil.which(tool) for tool in TOOLS), "requires Linux build tools")
class ExecutionPermissionTests(unittest.TestCase):
    def test_collects_wx_and_verifies_all_observations(self):
        with tempfile.TemporaryDirectory(prefix="wx lab ") as directory:
            output = Path(directory) / "host results"
            result = capture(output)
            self.assertEqual(result.returncode, 0, result.stderr.decode() + result.stdout.decode())
            self.assertTrue((output / "COMPLETE").exists())

            observations = json.loads((output / "observations.json").read_text())
            self.assertEqual(len(observations), 9)
            for row in observations:
                if row["mode"] == "rw":
                    # Non-executable mapping: the copied bytes must not run.
                    self.assertEqual(row["signal"], "SIGSEGV")
                    self.assertFalse(row["marker_printed"])
                elif row["mode"] == "rx":
                    # Executable mapping: the identical bytes run.
                    self.assertEqual(row["returncode"], 0)
                    self.assertTrue(row["marker_printed"])
                else:  # rwx is policy-dependent
                    self.assertTrue(row["marker_printed"] or row["mprotect_rejected"])

            finding = json.loads((output / "finding.json").read_text())
            self.assertTrue(finding["non_exec_page_faulted"])
            self.assertTrue(finding["exec_page_ran_identical_bytes"])
            # Exactly one of the rwx outcomes must hold, never both or neither.
            self.assertNotEqual(finding["write_exec_mapping_allowed"],
                                finding["write_exec_mapping_rejected"])

            exported = Path(directory) / "portable.json"
            export = subprocess.run([sys.executable, str(EXPORTER), str(output),
                                     "--output", str(exported)], capture_output=True, text=True)
            self.assertEqual(export.returncode, 0, export.stderr)
            portable = json.loads(exported.read_text())["captures"][0]
            self.assertEqual(len(portable["observations"]), 9)
            self.assertIn("<oracle>:", portable["oracle_disassembly"])
            self.assertEqual(portable["full_manifest_sha256"],
                             hashlib.sha256((output / "SHA256SUMS").read_bytes()).hexdigest())
            # A second export to the same path must refuse to overwrite.
            self.assertEqual(subprocess.run([sys.executable, str(EXPORTER), str(output),
                                             "--output", str(exported)], capture_output=True).returncode, 1)

            # Every manifest entry covers exactly the capture artifacts and hashes.
            artifacts = set()
            for line in (output / "SHA256SUMS").read_text().splitlines():
                digest, name = line.split("  ", 1)
                artifacts.add(name)
                self.assertEqual(hashlib.sha256((output / name).read_bytes()).hexdigest(), digest)
            expected = {str(path.relative_to(output)) for path in output.rglob("*") if path.is_file()}
            self.assertEqual(artifacts, expected - {"SHA256SUMS", "COMPLETE"})

            # Tampering with a covered artifact breaks the export.
            (output / "finding.json").write_text("tampered")
            rejected = Path(directory) / "rejected.json"
            self.assertEqual(subprocess.run([sys.executable, str(EXPORTER), str(output),
                                             "--output", str(rejected)], capture_output=True).returncode, 1)
            self.assertFalse(rejected.exists())

            # The binary requests a non-executable stack; no core dumps are left.
            elf = (output / "wx_probe.readelf.stdout.txt").read_text()
            stack = next(line for line in elf.splitlines() if "GNU_STACK" in line)
            self.assertIn("RW ", stack)
            self.assertNotIn("RWE", stack)
            self.assertFalse(list(output.rglob("core*")))

    def test_failed_build_retains_evidence_without_completion(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "failed"
            result = capture(output, "-fthis-flag-is-intentionally-invalid")
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((output / "COMPLETE").exists())
            self.assertFalse((output / "SHA256SUMS").exists())
            self.assertIn("-fthis-flag-is-intentionally-invalid", (output / "build.stderr.txt").read_text())

    def test_preserves_existing_output_and_rejects_invalid_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "existing"
            target.mkdir()
            marker = target / "marker"
            marker.write_text("keep this evidence")
            link = root / "dangling"
            link.symlink_to(root / "missing")
            for path in (target, marker, link):
                self.assertNotEqual(capture(path).returncode, 0)
            self.assertEqual(marker.read_text(), "keep this evidence")
            self.assertTrue(link.is_symlink())
            self.assertFalse((root / "missing").exists())

            invalid_out = root / "invalid"
            res = capture(invalid_out, label="invalid_label")
            self.assertEqual(res.returncode, 2)
            self.assertFalse(invalid_out.exists())


EVIDENCE_DIR = ROOT / "labs/07-execution-permission/evidence"


class RecordedEvidenceTests(unittest.TestCase):
    """Checks on the committed Lab 07 evidence; no build tools required."""

    def test_recorded_evidence_integrity(self):
        files = sorted(EVIDENCE_DIR.glob("*.json"))
        self.assertTrue(files, "no committed Lab 07 evidence found")
        for path in files:
            data = json.loads(path.read_text())
            self.assertTrue(data["captures"])
            for capture_entry in data["captures"]:
                self.assertIn(capture_entry["environment"]["label"], ("host", "modern"))
                self.assertEqual(len(capture_entry["observations"]), 9)
                self.assertTrue(capture_entry["full_manifest_sha256"])
                self.assertIn("<oracle>:", capture_entry["oracle_disassembly"])
                finding = capture_entry["finding"]
                self.assertTrue(finding["non_exec_page_faulted"])
                self.assertTrue(finding["exec_page_ran_identical_bytes"])
                self.assertNotEqual(finding["write_exec_mapping_allowed"],
                                    finding["write_exec_mapping_rejected"])
                modes = {row["mode"] for row in capture_entry["observations"]}
                self.assertEqual(modes, {"rw", "rx", "rwx"})
                for row in capture_entry["observations"]:
                    if row["mode"] == "rw":
                        self.assertEqual(row["signal"], "SIGSEGV")
                        self.assertFalse(row["marker_printed"])
                    elif row["mode"] == "rx":
                        self.assertEqual(row["returncode"], 0)
                        self.assertTrue(row["marker_printed"])


if __name__ == "__main__":
    unittest.main()
