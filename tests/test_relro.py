"""Real compiler and runtime checks for Lab 09 (GOT overwrite under RELRO)."""
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
SCRIPT = ROOT / "scripts" / "capture-relro.py"
EXPORTER = ROOT / "scripts" / "export-relro.py"
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
class RelroTests(unittest.TestCase):
    def test_collects_relro_and_verifies_all_observations(self):
        with tempfile.TemporaryDirectory(prefix="relro ") as directory:
            output = Path(directory) / "host results"
            result = capture(output)
            self.assertEqual(result.returncode, 0, result.stderr.decode() + result.stdout.decode())
            self.assertTrue((output / "COMPLETE").exists())

            observations = json.loads((output / "observations.json").read_text())
            self.assertEqual(len(observations), 6)
            for row in observations:
                if row["mode"] == "partial":
                    # Partial RELRO: the GOT is writable, the redirect works.
                    self.assertEqual(row["returncode"], 42)
                    self.assertTrue(row["target_reached"])
                else:  # full
                    # Full RELRO: the GOT is read-only, the write faults.
                    self.assertEqual(row["signal"], "SIGSEGV")
                    self.assertFalse(row["target_reached"])

            finding = json.loads((output / "finding.json").read_text())
            self.assertTrue(finding["partial_relro_got_is_writable"])
            self.assertTrue(finding["full_relro_got_is_read_only"])

            # Each build has its own puts GOT slot (full/partial lay it out
            # differently); both must be recorded.
            payload = json.loads((output / "payload.json").read_text())
            self.assertEqual(set(payload["puts_got_slot"]), {"got_full", "got_partial"})

            exported = Path(directory) / "portable.json"
            export = subprocess.run([sys.executable, str(EXPORTER), str(output),
                                     "--output", str(exported)], capture_output=True, text=True)
            self.assertEqual(export.returncode, 0, export.stderr)
            portable = json.loads(exported.read_text())["captures"][0]
            self.assertEqual(len(portable["observations"]), 6)
            self.assertEqual(portable["full_manifest_sha256"],
                             hashlib.sha256((output / "SHA256SUMS").read_bytes()).hexdigest())
            self.assertEqual(subprocess.run([sys.executable, str(EXPORTER), str(output),
                                             "--output", str(exported)], capture_output=True).returncode, 1)

            # Manifest covers exactly the capture artifacts and hashes.
            artifacts = set()
            for line in (output / "SHA256SUMS").read_text().splitlines():
                digest, name = line.split("  ", 1)
                artifacts.add(name)
                self.assertEqual(hashlib.sha256((output / name).read_bytes()).hexdigest(), digest)
            expected = {str(path.relative_to(output)) for path in output.rglob("*") if path.is_file()}
            self.assertEqual(artifacts, expected - {"SHA256SUMS", "COMPLETE"})

            (output / "payload.json").write_text("tampered")
            rejected = Path(directory) / "rejected.json"
            self.assertEqual(subprocess.run([sys.executable, str(EXPORTER), str(output),
                                             "--output", str(rejected)], capture_output=True).returncode, 1)
            self.assertFalse(rejected.exists())

            # RELRO shape: both GNU_RELRO; only full has BIND_NOW. Non-PIE, no guard.
            lab = output / "09-relro-got"
            for binary, bind_now in (("got_full", True), ("got_partial", False)):
                elf = (output / (binary + ".readelf.stdout.txt")).read_text()
                self.assertIn("Type:                              EXEC", elf)
                self.assertIn("GNU_RELRO", elf)
                self.assertNotIn("__stack_chk_fail", elf)
                self.assertEqual("BIND_NOW" in elf, bind_now)
                for args, code in (([], 64), (["notaddr"], 64)):
                    res = subprocess.run([str(lab / binary), *args], capture_output=True, timeout=5)
                    self.assertEqual(res.returncode, code, res.stderr)
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


EVIDENCE_DIR = ROOT / "labs/09-relro-got/evidence"


class RecordedEvidenceTests(unittest.TestCase):
    """Checks on the committed Lab 09 evidence; no build tools required."""

    def test_recorded_evidence_integrity(self):
        files = sorted(EVIDENCE_DIR.glob("*.json"))
        self.assertTrue(files, "no committed Lab 09 evidence found")
        for path in files:
            data = json.loads(path.read_text())
            self.assertTrue(data["captures"])
            for capture_entry in data["captures"]:
                self.assertIn(capture_entry["environment"]["label"], ("host", "modern"))
                self.assertEqual(len(capture_entry["observations"]), 6)
                self.assertTrue(capture_entry["full_manifest_sha256"])
                finding = capture_entry["finding"]
                self.assertTrue(finding["partial_relro_got_is_writable"])
                self.assertTrue(finding["full_relro_got_is_read_only"])
                modes = {row["mode"] for row in capture_entry["observations"]}
                self.assertEqual(modes, {"partial", "full"})
                for row in capture_entry["observations"]:
                    if row["mode"] == "partial":
                        self.assertEqual(row["returncode"], 42)
                        self.assertTrue(row["target_reached"])
                    else:
                        self.assertEqual(row["signal"], "SIGSEGV")
                        self.assertFalse(row["target_reached"])


if __name__ == "__main__":
    unittest.main()
