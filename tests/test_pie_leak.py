"""Real compiler and runtime checks for Lab 06 (defeating PIE with a leak)."""
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
SCRIPT = ROOT / "scripts" / "capture-pie-leak.py"
EXPORTER = ROOT / "scripts" / "export-pie-leak.py"
TOOLS = ("gcc", "make", "nm", "readelf", "objdump", "gdb", "getconf")


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


@unittest.skipUnless(all(shutil.which(tool) for tool in TOOLS), "requires Linux build tools, nm and gdb")
class PieLeakTests(unittest.TestCase):
    def test_collects_pie_leak_and_verifies_all_observations(self):
        with tempfile.TemporaryDirectory(prefix="pie leak ") as directory:
            output = Path(directory) / "host results"
            result = capture(output)
            self.assertEqual(result.returncode, 0, result.stderr.decode() + result.stdout.decode())
            self.assertTrue((output / "COMPLETE").exists())
            self.assertTrue((output / "environment.json").exists())

            payload_info = json.loads((output / "payload.json").read_text())
            self.assertEqual(payload_info["saved_return_offset"], 40)
            self.assertEqual(payload_info["payload_bytes"], 56)

            observations = json.loads((output / "observations.json").read_text())
            self.assertEqual(len(observations), 9)
            # The leaked base must vary across runs, or ASLR is not in effect and
            # the entire result is meaningless.
            self.assertGreater(len({row["leaked_reference"] for row in observations}), 1)
            # The stale fault is measured, not assumed: the fault PC must sit in
            # the stale text range and not in the session's own range.
            stale_fault = json.loads((output / "stale-fault.json").read_text())
            self.assertTrue(stale_fault["fault_in_stale_text_range"])
            self.assertFalse(stale_fault["fault_in_session_text_range"])
            self.assertNotEqual(stale_fault["stale_base"], stale_fault["session_base"])
            # The separate stale leak is kept as a raw artifact for reproducibility.
            self.assertTrue((output / "stale.1.source.stdout.txt").exists())
            self.assertIn("LEAK", (output / "stale.1.source.stdout.txt").read_text())
            for row in observations:
                if row["mode"] == "bypass":
                    self.assertEqual(row["returncode"], 42)
                    self.assertTrue(row["target_reached"])
                    self.assertFalse(row["returned_from_overflow"])
                    self.assertFalse(row["stale_base"])
                    reference_link = int(payload_info["reference_symbol_link"], 16)
                    session_base = int(row["leaked_reference"], 16) - reference_link
                    self.assertEqual(int(row["attacked_base"], 16), session_base)
                elif row["mode"] == "stale":
                    self.assertEqual(row["signal"], "SIGSEGV")
                    self.assertFalse(row["target_reached"])
                    # The negative control must attack a base other than this
                    # session's own, or it would not model a stale address.
                    self.assertTrue(row["stale_base"])
                    reference_link = int(payload_info["reference_symbol_link"], 16)
                    session_base = int(row["leaked_reference"], 16) - reference_link
                    self.assertNotEqual(int(row["attacked_base"], 16), session_base)
                else:  # fixed
                    self.assertEqual(row["returncode"], 2)
                    self.assertFalse(row["target_reached"])

            exported = Path(directory) / "portable.json"
            export = subprocess.run([sys.executable, str(EXPORTER), str(output),
                                     "--output", str(exported)], capture_output=True, text=True)
            self.assertEqual(export.returncode, 0, export.stderr)
            portable = json.loads(exported.read_text())["captures"][0]
            self.assertEqual(len(portable["observations"]), 9)
            self.assertGreaterEqual(portable["distinct_leaked_bases"], 2)
            # The negative control's provenance must travel in the portable JSON.
            self.assertEqual(len(portable["stale_sources"]), 3)
            for source in portable["stale_sources"]:
                self.assertIn("LEAK", source["leak_stdout"])
                self.assertEqual(source["returncode"], 0)
            self.assertIn("SIGSEGV", portable["stale_fault_gdb"])
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
            (output / "payload.json").write_text("tampered")
            rejected = Path(directory) / "rejected.json"
            self.assertEqual(subprocess.run([sys.executable, str(EXPORTER), str(output),
                                             "--output", str(rejected)], capture_output=True).returncode, 1)
            self.assertFalse(rejected.exists())

            # Both binaries are PIE, non-exec stack, RELRO/BIND_NOW, no guard.
            lab = output / "06-pie-leak-bypass"
            for binary in ("pie_bypass", "pie_fixed"):
                elf = (output / (binary + ".readelf.stdout.txt")).read_text()
                self.assertIn("Type:                              DYN", elf)
                self.assertNotIn("__stack_chk_fail", elf)
                self.assertIn("GNU_RELRO", elf)
                self.assertIn("BIND_NOW", elf)
                stack = next(line for line in elf.splitlines() if "GNU_STACK" in line)
                self.assertIn("RW ", stack)
                self.assertNotIn("RWE", stack)
                # The usage path rejects malformed invocations.
                for args, code in (([], 64), (["bogus"], 64)):
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
            self.assertTrue((output / "environment.json").exists())
            self.assertIn("-fthis-flag-is-intentionally-invalid", (output / "build.stderr.txt").read_text())

    def test_fixed_everywhere_breaks_the_bypass_case(self):
        # Building both binaries with the bounds check removes the overflow path,
        # so the bypass case can no longer redirect and the capture must fail
        # without COMPLETE.
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "all-fixed"
            result = capture(output, "-O0 -g -Wall -Wextra -DFIXED")
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((output / "COMPLETE").exists())
            self.assertFalse((output / "SHA256SUMS").exists())

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
            self.assertEqual(list(target.iterdir()), [marker])
            self.assertTrue(link.is_symlink())
            self.assertFalse((root / "missing").exists())

            invalid_out = root / "invalid"
            res = capture(invalid_out, label="invalid_label")
            self.assertEqual(res.returncode, 2)
            self.assertFalse(invalid_out.exists())


EVIDENCE_DIR = ROOT / "labs/06-pie-leak-bypass/evidence"


class RecordedEvidenceTests(unittest.TestCase):
    """Checks on the committed Lab 06 evidence; no build tools required."""

    def test_recorded_evidence_integrity(self):
        files = sorted(EVIDENCE_DIR.glob("*.json"))
        self.assertTrue(files, "no committed Lab 06 evidence found")
        for path in files:
            data = json.loads(path.read_text())
            self.assertTrue(data["captures"])
            for capture_entry in data["captures"]:
                self.assertIn(capture_entry["environment"]["label"], ("host", "modern"))
                self.assertEqual(len(capture_entry["observations"]), 9)
                self.assertGreaterEqual(capture_entry["distinct_leaked_bases"], 2)
                self.assertTrue(capture_entry["full_manifest_sha256"])
                self.assertEqual(capture_entry["payload"]["saved_return_offset"], 40)
                self.assertTrue(capture_entry["stale_fault"]["fault_in_stale_text_range"])
                self.assertFalse(capture_entry["stale_fault"]["fault_in_session_text_range"])
                reference_link = int(capture_entry["payload"]["reference_symbol_link"], 16)
                modes = {row["mode"] for row in capture_entry["observations"]}
                self.assertEqual(modes, {"bypass", "stale", "fixed"})
                for row in capture_entry["observations"]:
                    session_base = int(row["leaked_reference"], 16) - reference_link
                    if row["mode"] == "bypass":
                        self.assertEqual(row["returncode"], 42)
                        self.assertTrue(row["target_reached"])
                        self.assertEqual(int(row["attacked_base"], 16), session_base)
                    elif row["mode"] == "stale":
                        self.assertEqual(row["signal"], "SIGSEGV")
                        self.assertFalse(row["target_reached"])
                        self.assertNotEqual(int(row["attacked_base"], 16), session_base)
                    else:
                        self.assertEqual(row["returncode"], 2)
                        self.assertFalse(row["target_reached"])


if __name__ == "__main__":
    unittest.main()
