"""Real compiler and runtime checks for Lab 05 (return-address overwrite under mitigations)."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "capture-return-overwrite.py"
EXPORTER = ROOT / "scripts" / "export-return-overwrite.py"
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
class ReturnOverwriteTests(unittest.TestCase):
    def test_collects_return_overwrite_and_verifies_all_observations(self):
        with tempfile.TemporaryDirectory(prefix="overwrite lab ") as directory:
            output = Path(directory) / "host results"
            result = capture(output)
            self.assertEqual(result.returncode, 0, result.stderr.decode() + result.stdout.decode())
            self.assertTrue((output / "COMPLETE").exists())
            self.assertTrue((output / "environment.json").exists())
            payload_info = json.loads((output / "payload.json").read_text())
            self.assertEqual(payload_info["padding_bytes"], 40)
            self.assertEqual(payload_info["payload_bytes"], 56)
            self.assertEqual(payload_info["offsets"]["overwrite_plain"], payload_info["offsets"]["overwrite_pie"])
            self.assertIn("LAB05_TARGET_RSP_MOD16=8", (output / "target-trace.stdout.txt").read_text())

            observations = json.loads((output / "observations.json").read_text())
            self.assertEqual(len(observations), 27)
            exported = Path(directory) / "portable.json"
            export = subprocess.run([sys.executable, str(EXPORTER), str(output),
                                     "--output", str(exported)], capture_output=True, text=True)
            self.assertEqual(export.returncode, 0, export.stderr)
            portable = json.loads(exported.read_text())["captures"][0]
            self.assertEqual(len(portable["observations"]), 27)
            self.assertEqual(portable["full_manifest_sha256"],
                             hashlib.sha256((output / "SHA256SUMS").read_bytes()).hexdigest())
            self.assertEqual(subprocess.run([sys.executable, str(EXPORTER), str(output),
                                             "--output", str(exported)], capture_output=True).returncode, 1)

            for row in observations:
                binary = row["binary"]
                mode = row["mode"]
                if mode == "safe":
                    self.assertEqual(row["returncode"], 0)
                    self.assertTrue(row["returned_from_copy"])
                    self.assertFalse(row["target_reached"])
                elif binary == "overwrite_plain" and mode == "attack":
                    self.assertEqual(row["returncode"], 42)
                    self.assertTrue(row["target_reached"])
                    self.assertFalse(row["returned_from_copy"])
                elif binary == "overwrite_plain" and mode == "padding":
                    self.assertEqual(row["signal"], "SIGSEGV")
                    self.assertFalse(row["target_reached"])
                elif binary == "overwrite_canary" and mode == "attack":
                    self.assertEqual(row["signal"], "SIGABRT")
                    self.assertFalse(row["target_reached"])
                    self.assertFalse(row["returned_from_copy"])
                elif binary == "overwrite_pie" and mode == "attack":
                    self.assertEqual(row["signal"], "SIGSEGV")
                    self.assertFalse(row["target_reached"])
                    self.assertFalse(row["returned_from_copy"])
                elif binary == "overwrite_fixed" and mode == "attack":
                    self.assertEqual(row["returncode"], 2)
                    self.assertFalse(row["target_reached"])
                    self.assertFalse(row["returned_from_copy"])

            artifacts = set()
            for line in (output / "SHA256SUMS").read_text().splitlines():
                digest, name = line.split("  ", 1)
                artifacts.add(name)
                self.assertEqual(hashlib.sha256((output / name).read_bytes()).hexdigest(), digest)
            expected = {str(path.relative_to(output)) for path in output.rglob("*") if path.is_file()}
            self.assertEqual(artifacts, expected - {"SHA256SUMS", "COMPLETE"})
            (output / "safe.input").write_bytes(b"tampered")
            rejected = Path(directory) / "rejected.json"
            self.assertEqual(subprocess.run([sys.executable, str(EXPORTER), str(output),
                                             "--output", str(rejected)], capture_output=True).returncode, 1)
            self.assertFalse(rejected.exists())

            lab = output / "05-return-address-overwrite"
            for binary in ("overwrite_plain", "overwrite_canary", "overwrite_pie", "overwrite_fixed"):
                elf = (output / (binary + ".readelf.stdout.txt")).read_text()
                self.assertEqual("__stack_chk_fail" in elf, binary == "overwrite_canary")
                self.assertIn("GNU_RELRO", elf)
                self.assertIn("BIND_NOW", elf)
                stack = next(line for line in elf.splitlines() if "GNU_STACK" in line)
                self.assertIn("RW ", stack)
                self.assertNotIn("RWE", stack)
                for args, data, code in (
                    ([], b"", 64),
                    (["0"], b"", 64),
                    (["129"], b"", 64),
                    (["typo"], b"", 64),
                    (["16"], b"A" * 8, 3),
                ):
                    res = subprocess.run([str(lab / binary), *args], input=data, capture_output=True, timeout=5)
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
            build_log = (output / "build.stderr.txt").read_text()
            self.assertIn("-fthis-flag-is-intentionally-invalid", build_log)

    def test_unexpected_runtime_result_is_rejected_without_completion(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "unexpected"
            result = capture(output, "-O0 -g -Wall -Wextra -DFIXED")
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((output / "COMPLETE").exists())
            self.assertFalse((output / "SHA256SUMS").exists())
            self.assertIn("rejected", (output / "target-trace.stdout.txt").read_text() + (output / "target-trace.stderr.txt").read_text())

    def test_timeout_retains_partial_output_without_completion(self):
        spec = importlib.util.spec_from_file_location("overwrite_capture", SCRIPT)
        collector = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(collector)
        original_run = collector.subprocess.run

        def timed_out_binary(command, **kwargs):
            if Path(command[0]).name == "overwrite_plain" and len(command) == 2:
                raise subprocess.TimeoutExpired(command, 30, output=b"partial stdout", stderr=b"partial stderr")
            return original_run(command, **kwargs)

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "timeout"
            env = {key: value for key, value in os.environ.items() if key not in ("CC", "CFLAGS", "LDFLAGS")}
            with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(collector.resource, "setrlimit"), mock.patch.object(collector.subprocess, "run", side_effect=timed_out_binary):
                with self.assertRaises(subprocess.TimeoutExpired):
                    collector.capture("host", output)
            self.assertFalse((output / "COMPLETE").exists())
            self.assertEqual((output / "overwrite_plain.safe.1.stdout.txt").read_bytes(), b"partial stdout")
            self.assertEqual((output / "overwrite_plain.safe.1.stderr.txt").read_bytes(), b"partial stderr")
            self.assertEqual(json.loads((output / "overwrite_plain.safe.1.timeout.json").read_text())["timeout_seconds"], 30)

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


EVIDENCE_FILE = ROOT / "labs/05-return-address-overwrite/evidence/2026-11-03.json"


class RecordedEvidenceTests(unittest.TestCase):
    """Checks on the committed Lab 05 evidence; no build tools required."""

    def test_recorded_evidence_integrity(self):
        data = json.loads(EVIDENCE_FILE.read_text())
        self.assertEqual({c["environment"]["label"] for c in data["captures"]}, {"host", "modern"})
        self.assertEqual(len(data["captures"]), 2)
        for capture_entry in data["captures"]:
            self.assertEqual(len(capture_entry["observations"]), 27)
            self.assertTrue(capture_entry["full_manifest_sha256"])
            self.assertEqual(capture_entry["payload"]["padding_bytes"], 40)
            self.assertEqual(capture_entry["payload"]["payload_bytes"], 56)

    # RESULTS.md toolchain versions are checked against the evidence for every
    # lab by tests/test_results_consistency.py.


if __name__ == "__main__":
    unittest.main()
