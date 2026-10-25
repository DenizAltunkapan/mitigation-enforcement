"""Real compiler and runtime checks for the controlled stack-canary lab."""
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
SCRIPT = ROOT / "scripts" / "capture-stack-canary.py"
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
class StackCanaryTests(unittest.TestCase):
    def test_controlled_experiment_and_integrity_at_two_optimization_levels(self):
        for optimization in ("-O0", "-O2"):
            with self.subTest(optimization=optimization), tempfile.TemporaryDirectory(prefix="canary lab ") as directory:
                output = Path(directory) / "host results"
                result = capture(output, optimization + " -g -Wall -Wextra -Werror -fno-omit-frame-pointer")
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.assertTrue((output / "COMPLETE").exists())
                lab = output / "04-stack-canary"
                observations = json.loads((lab / "observations.json").read_text())
                self.assertEqual(len(observations), 18)
                for row in observations:
                    if row["mode"] == "safe":
                        self.assertEqual(row["returncode"], 0)
                        self.assertTrue(row["returned_from_copy"])
                    elif row["binary"] == "stack_canary":
                        self.assertEqual(row["signal"], "SIGABRT")
                        self.assertFalse(row["returned_from_copy"])
                    elif row["binary"] == "stack_fixed":
                        self.assertEqual(row["returncode"], 2)
                        self.assertFalse(row["returned_from_copy"])
                artifacts = set()
                for line in (output / "SHA256SUMS").read_text().splitlines():
                    digest, name = line.split("  ", 1)
                    artifacts.add(name)
                    self.assertEqual(hashlib.sha256((output / name).read_bytes()).hexdigest(), digest)
                expected = {str(path.relative_to(output)) for path in output.rglob("*") if path.is_file()}
                self.assertEqual(artifacts, expected - {"SHA256SUMS", "COMPLETE"})
                self.assertIn("src/stack_copy.c", {str(Path(name).relative_to("04-stack-canary")) for name in artifacts if name.startswith("04-stack-canary/")})
                for binary in ("stack_unprotected", "stack_canary", "stack_fixed"):
                    elf = (lab / (binary + ".readelf.txt")).read_text()
                    self.assertEqual("__stack_chk_fail" in elf, binary != "stack_unprotected")
                    self.assertIn("GNU_RELRO", elf)
                    self.assertIn("BIND_NOW", elf)
                    stack = next(line for line in elf.splitlines() if "GNU_STACK" in line)
                    self.assertIn("RW ", stack)
                    self.assertNotIn("RWE", stack)
                    # Argument errors and short input are ordinary errors, not crashes.
                    for args, data, code in (([], b"", 64), (["typo"], b"", 64), (["safe"], b"A" * 8, 3)):
                        result = subprocess.run([str(lab / binary), *args], input=data, capture_output=True, timeout=5)
                        self.assertEqual(result.returncode, code, result.stderr)
                self.assertFalse(list(output.rglob("core*")))

    def test_failed_build_retains_evidence_without_completion(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "failed"
            result = capture(output, "-fintentionally-invalid-option")
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((output / "COMPLETE").exists())
            self.assertFalse((output / "SHA256SUMS").exists())
            self.assertTrue((output / "environment.json").exists())
            self.assertIn("-fintentionally-invalid-option", (output / "04-stack-canary" / "build.txt").read_text())

    def test_unexpected_runtime_result_is_recorded_and_not_marked_complete(self):
        # Force the bounds fix into every variant: the canary case must now
        # reject rather than abort. The collector must reject this experiment,
        # even though it is run with Python's assertion optimization enabled.
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "unexpected"
            result = capture(output, "-O0 -g -Wall -Wextra -DFIXED")
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((output / "COMPLETE").exists())
            lab = output / "04-stack-canary"
            rows = json.loads((lab / "observations.json").read_text())
            self.assertEqual(rows[-1]["binary"], "stack_canary")
            self.assertEqual(rows[-1]["mode"], "overflow")
            self.assertEqual(rows[-1]["returncode"], 2)
            self.assertIn("rejected", (lab / "stack_canary.overflow.1.stderr.txt").read_text())

    def test_timeout_retains_partial_output_without_completion(self):
        spec = importlib.util.spec_from_file_location("canary_capture", SCRIPT)
        collector = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(collector)
        original_run = collector.run

        def timed_out_binary(command, **kwargs):
            if Path(command[0]).name == "stack_unprotected":
                raise subprocess.TimeoutExpired(command, 30, output=b"partial stdout", stderr=b"partial stderr")
            return original_run(command, **kwargs)

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "timeout"
            env = {key: value for key, value in os.environ.items() if key not in ("CC", "CFLAGS", "LDFLAGS")}
            # No binary runs in this test; avoid changing the test runner's limit.
            with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(collector.resource, "setrlimit"), mock.patch.object(collector, "run", side_effect=timed_out_binary):
                with self.assertRaises(subprocess.TimeoutExpired):
                    collector.capture("host", output)
            self.assertFalse((output / "COMPLETE").exists())
            lab = output / "04-stack-canary"
            self.assertEqual((lab / "stack_unprotected.safe.1.stdout.txt").read_bytes(), b"partial stdout")
            self.assertEqual((lab / "stack_unprotected.safe.1.stderr.txt").read_bytes(), b"partial stderr")
            self.assertEqual(json.loads((lab / "stack_unprotected.safe.1.timeout.json").read_text())["timeout_seconds"], 30)

    def test_existing_directory_file_and_dangling_symlink_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "existing"
            target.mkdir()
            marker = target / "marker"
            marker.write_text("keep")
            link = root / "dangling"
            link.symlink_to(root / "missing")
            for path in (target, marker, link):
                self.assertNotEqual(capture(path).returncode, 0)
            self.assertEqual(marker.read_text(), "keep")
            self.assertEqual(list(target.iterdir()), [marker])
            self.assertTrue(link.is_symlink())
            self.assertFalse((root / "missing").exists())

    def test_invalid_label_creates_no_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "invalid"
            result = capture(output, label="typo")
            self.assertEqual(result.returncode, 2)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
