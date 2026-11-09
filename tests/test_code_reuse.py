"""Real compiler and runtime checks for Lab 08 (code reuse under a non-exec stack)."""
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
SCRIPT = ROOT / "scripts" / "capture-code-reuse.py"
EXPORTER = ROOT / "scripts" / "export-code-reuse.py"
TOOLS = ("gcc", "make", "nm", "readelf", "objdump", "gdb", "getconf")


def capture(output, flags=None, label="host"):
    env = os.environ.copy()
    for key in ("CC", "CFLAGS", "LDFLAGS"):
        env.pop(key, None)
    if flags is not None:
        env["CFLAGS"] = flags
    return subprocess.run(
        [sys.executable, "-O", str(SCRIPT), label, str(output)],
        cwd="/tmp", env=env, capture_output=True, timeout=120,
    )


@unittest.skipUnless(all(shutil.which(tool) for tool in TOOLS), "requires Linux build tools and gdb")
class CodeReuseTests(unittest.TestCase):
    def test_collects_code_reuse_and_verifies_all_observations(self):
        with tempfile.TemporaryDirectory(prefix="code reuse ") as directory:
            output = Path(directory) / "host results"
            result = capture(output)
            self.assertEqual(result.returncode, 0, result.stderr.decode() + result.stdout.decode())
            self.assertTrue((output / "COMPLETE").exists())

            observations = json.loads((output / "observations.json").read_text())
            self.assertEqual(len(observations), 9)
            for row in observations:
                if row["mode"] == "chain":
                    # Code reuse chains stage_one -> stage_two -> oracle in order.
                    self.assertEqual(row["returncode"], 42)
                    self.assertTrue(row["target_reached"])
                    self.assertTrue(row["stage_one_ran"] and row["stage_two_ran"])
                elif row["mode"] == "partial":
                    self.assertEqual(row["returncode"], 43)
                    self.assertFalse(row["stage_one_ran"])
                else:  # fixed
                    self.assertEqual(row["returncode"], 2)
                    self.assertFalse(row["target_reached"])

            # The NX control is measured in-process: the fault PC equals the live
            # stack buffer and lies in a non-executable [stack] mapping, so the
            # SIGSEGV is a blocked stack execution, not a jump to unmapped memory.
            nx = json.loads((output / "nx-fault.json").read_text())
            self.assertTrue(nx["fault_pc_equals_stack_buffer"])
            self.assertTrue(nx["fault_pc_in_stack_mapping"])
            self.assertTrue(nx["stack_mapping_non_executable"])
            self.assertEqual(nx["fault_pc"], nx["stack_buffer"])
            self.assertNotIn("x", nx["stack_perms"])

            finding = json.loads((output / "finding.json").read_text())
            self.assertTrue(finding["stack_shellcode_blocked_by_nx"])
            self.assertTrue(finding["nx_fault_pc_equals_stack_buffer"])
            self.assertTrue(finding["nx_fault_in_non_executable_stack"])
            self.assertTrue(finding["code_reuse_chain_reached_oracle"])
            self.assertTrue(finding["chain_required_correct_order"])
            self.assertTrue(finding["bounds_check_prevented_redirection"])

            exported = Path(directory) / "portable.json"
            export = subprocess.run([sys.executable, str(EXPORTER), str(output),
                                     "--output", str(exported)], capture_output=True, text=True)
            self.assertEqual(export.returncode, 0, export.stderr)
            portable = json.loads(exported.read_text())["captures"][0]
            self.assertEqual(len(portable["observations"]), 9)
            self.assertTrue(portable["nx_fault"]["fault_pc_equals_stack_buffer"])
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

            lab = output / "08-code-reuse-chain"
            for binary in ("code_reuse", "code_reuse_fixed"):
                elf = (output / (binary + ".readelf.stdout.txt")).read_text()
                self.assertIn("Type:                              EXEC", elf)
                self.assertNotIn("__stack_chk_fail", elf)
                stack = next(line for line in elf.splitlines() if "GNU_STACK" in line)
                self.assertIn("RW ", stack)
                self.assertNotIn("RWE", stack)
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
            self.assertIn("-fthis-flag-is-intentionally-invalid", (output / "build.stderr.txt").read_text())

    def test_fixed_everywhere_blocks_the_chain(self):
        # Building both binaries with the bounds check removes the overflow path,
        # so the chain case can no longer redirect and the capture must fail.
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "all-fixed"
            result = capture(output, "-O0 -g -Wall -Wextra -DFIXED")
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((output / "COMPLETE").exists())

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


EVIDENCE_DIR = ROOT / "labs/08-code-reuse-chain/evidence"


class RecordedEvidenceTests(unittest.TestCase):
    """Checks on the committed Lab 08 evidence; no build tools required."""

    def test_recorded_evidence_integrity(self):
        files = sorted(EVIDENCE_DIR.glob("*.json"))
        self.assertTrue(files, "no committed Lab 08 evidence found")
        for path in files:
            data = json.loads(path.read_text())
            self.assertTrue(data["captures"])
            for capture_entry in data["captures"]:
                self.assertIn(capture_entry["environment"]["label"], ("host", "modern"))
                self.assertEqual(len(capture_entry["observations"]), 9)
                self.assertTrue(capture_entry["full_manifest_sha256"])
                nx = capture_entry["nx_fault"]
                self.assertEqual(nx["fault_pc"], nx["stack_buffer"])
                self.assertTrue(nx["fault_pc_in_stack_mapping"])
                self.assertTrue(nx["stack_mapping_non_executable"])
                finding = capture_entry["finding"]
                self.assertTrue(finding["stack_shellcode_blocked_by_nx"])
                self.assertTrue(finding["nx_fault_pc_equals_stack_buffer"])
                self.assertTrue(finding["code_reuse_chain_reached_oracle"])
                self.assertTrue(finding["chain_required_correct_order"])
                self.assertTrue(finding["bounds_check_prevented_redirection"])
                modes = {row["mode"] for row in capture_entry["observations"]}
                self.assertEqual(modes, {"chain", "partial", "fixed"})
                for row in capture_entry["observations"]:
                    if row["mode"] == "chain":
                        self.assertEqual(row["returncode"], 42)
                        self.assertTrue(row["target_reached"])
                    elif row["mode"] == "fixed":
                        self.assertEqual(row["returncode"], 2)
                        self.assertFalse(row["target_reached"])


if __name__ == "__main__":
    unittest.main()
