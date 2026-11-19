"""Real compiler and runtime checks for Lab 13 (partial instrumentation across a
shared-library boundary).

Verifies:
  * 2x2 instrumentation matrix (neither / main_only / lib_only / both) x
    2 overflow locations (in_main / in_lib) x 3 modes (safe / attack / fixed)
  * Main-binary-only baseline oracle reports 1 false positive (main_only/in_lib)
    and 1 false negative (lib_only/in_lib) across the 8 attack cells
  * Explicit bounds check (`fixed`) blocks pre-write in all 4 configs
  * End-to-end counter-finding export: a silent guard failure stays COMPLETE
    with hypothesis_supported=False and exports cleanly
  * Committed evidence integrity and prose consistency (no build tools needed)
"""
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

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "capture-boundary.py"
EXPORTER = ROOT / "scripts" / "export-boundary.py"
TOOLS = ("gcc", "make", "readelf", "objdump", "getconf")


def _load_collector():
    spec = importlib.util.spec_from_file_location("capture_boundary", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(ROOT / "scripts" / "research"))
    spec.loader.exec_module(module)
    return module


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


@unittest.skipUnless(all(shutil.which(tool) for tool in TOOLS), "requires Linux build tools")
class BoundaryInstrumentationTests(unittest.TestCase):
    def test_collects_boundary_matrix_and_baseline_oracle(self):
        with tempfile.TemporaryDirectory(prefix="boundary ") as directory:
            output = Path(directory) / "host results"
            result = capture(output)
            self.assertEqual(result.returncode, 0,
                             result.stderr.decode() + result.stdout.decode())
            self.assertTrue((output / "COMPLETE").exists())

            observations = json.loads((output / "observations.json").read_text())
            self.assertEqual(len(observations), 72)  # 4 configs * 2 locs * 3 modes * 3 repeats

            for row in observations:
                if row["mode"] == "safe":
                    self.assertEqual(row["returncode"], 0)
                    self.assertTrue(row["copy_completed"])
                    self.assertFalse(row["canary_abort"])
                elif row["mode"] == "fixed":
                    self.assertEqual(row["returncode"], 2)
                    self.assertTrue(row["bounds_rejected"])
                    self.assertFalse(row["copy_completed"])
                elif row["config"] == "neither":
                    self.assertFalse(row["canary_abort"])

            coverage = json.loads((output / "coverage.json").read_text())
            self.assertEqual(coverage["buf_size"], 32)
            self.assertEqual(coverage["emitted_but_not_effective_count"], 0)
            by_cell = {(c["config"], c["location"]): c for c in coverage["cells"]}
            for key in (("main_only", "in_main"), ("lib_only", "in_lib"),
                        ("both", "in_main"), ("both", "in_lib")):
                self.assertTrue(by_cell[key]["target_component_emitted_canary"], key)
                self.assertTrue(by_cell[key]["effective"], key)
            for key in (("neither", "in_main"), ("neither", "in_lib"),
                        ("main_only", "in_lib"), ("lib_only", "in_main")):
                self.assertFalse(by_cell[key]["target_component_emitted_canary"], key)
                self.assertFalse(by_cell[key]["effective"], key)

            oracle = json.loads((output / "main_only_oracle.json").read_text())
            self.assertEqual(oracle["false_positive_count"], 1)
            self.assertEqual(oracle["false_negative_count"], 1)
            self.assertEqual(oracle["misclassified_count"], 2)

            finding = json.loads((output / "finding.json").read_text())
            self.assertTrue(finding["both_protects_main_and_lib"])
            self.assertTrue(finding["main_only_leaves_lib_unprotected"])
            self.assertTrue(finding["lib_only_leaves_main_unprotected"])
            self.assertTrue(finding["neither_protects_neither"])
            self.assertTrue(finding["bounds_check_blocks_all_configs"])
            self.assertEqual(finding["main_only_oracle_false_positives"], 1)
            self.assertEqual(finding["main_only_oracle_false_negatives"], 1)
            self.assertTrue(finding["control_validity"])
            self.assertTrue(finding["hypothesis_supported"])

            states = json.loads((output / "states.json").read_text())
            self.assertTrue(states["capture_complete"])
            self.assertTrue(states["control_validity"])
            self.assertTrue(states["hypothesis_supported"])
            self.assertTrue(states["regression_gate_passed"])

            exported = Path(directory) / "portable.json"
            export = subprocess.run(
                [sys.executable, "-O", str(EXPORTER), str(output), "--output", str(exported)],
                capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(export.returncode, 0, export.stderr)
            portable = json.loads(exported.read_text())["captures"][0]
            self.assertEqual(len(portable["observations"]), 72)
            self.assertEqual(portable["states"], states)
            self.assertEqual(portable["main_only_oracle"], oracle)
            self.assertEqual(portable["full_manifest_sha256"],
                             hashlib.sha256((output / "SHA256SUMS").read_bytes()).hexdigest())
            self.assertEqual(
                subprocess.run([sys.executable, "-O", str(EXPORTER), str(output),
                                "--output", str(exported)], capture_output=True).returncode,
                1,
            )

            artifacts = set()
            for line in (output / "SHA256SUMS").read_text().splitlines():
                digest, name = line.split("  ", 1)
                artifacts.add(name)
                self.assertEqual(hashlib.sha256((output / name).read_bytes()).hexdigest(), digest)
            expected = {str(path.relative_to(output)) for path in output.rglob("*") if path.is_file()}
            self.assertEqual(artifacts, expected - {"SHA256SUMS", "COMPLETE"})

            (output / "coverage.json").write_text("tampered")
            rejected = Path(directory) / "rejected.json"
            self.assertEqual(
                subprocess.run([sys.executable, "-O", str(EXPORTER), str(output),
                                "--output", str(rejected)], capture_output=True).returncode,
                1,
            )
            self.assertFalse(rejected.exists())
            self.assertFalse(list(output.rglob("core*")))

    def test_silent_guard_failure_exports_end_to_end_as_counter_finding(self):
        collector = _load_collector()
        from outcomes import annotate, capture_states  # noqa: E402

        with tempfile.TemporaryDirectory(prefix="boundary cf ") as directory:
            output = Path(directory) / "host results"
            self.assertEqual(capture(output).returncode, 0)

            observations = json.loads((output / "observations.json").read_text())
            target = [r for r in observations if r["config"] == "main_only"
                      and r["location"] == "in_main" and r["mode"] == "attack"]
            self.assertEqual(len(target), 3)

            for row in target:
                row["returncode"], row["signal"] = -11, "SIGSEGV"
                row["copy_completed"], row["canary_abort"], row["bounds_rejected"] = False, False, False
                stem = "{config}.{location}.{mode}.{repeat}".format(**row)
                (output / (stem + ".stdout.txt")).write_text("")
                (output / (stem + ".stderr.txt")).write_text("")
                (output / (stem + ".status.json")).write_text(
                    json.dumps({"returncode": -11}) + "\n")
            (output / "observations.json").write_text(json.dumps(observations, indent=2) + "\n")

            annotated = annotate(observations, collector.LAB_POLICY)
            states = capture_states(observations, collector.LAB_POLICY,
                                    control_valid=True, capture_complete=True)
            self.assertTrue(states["capture_complete"])
            self.assertFalse(states["hypothesis_supported"])
            self.assertFalse(states["regression_gate_passed"])

            (output / "states.json").write_text(json.dumps(states, indent=2) + "\n")
            (output / "classified.json").write_text(json.dumps(
                [{"config": r["config"], "location": r["location"], "mode": r["mode"],
                  "repeat": r["repeat"], "outcome": r["outcome"],
                  "hypothesis_supported": r["hypothesis_supported"]} for r in annotated],
                indent=2) + "\n")
            finding = json.loads((output / "finding.json").read_text())
            finding["hypothesis_supported"] = states["hypothesis_supported"]
            (output / "finding.json").write_text(json.dumps(finding, indent=2) + "\n")

            (output / "SHA256SUMS").unlink()
            (output / "COMPLETE").unlink()
            manifest = [hashlib.sha256(p.read_bytes()).hexdigest() + "  "
                        + str(p.relative_to(output))
                        for p in sorted(output.rglob("*")) if p.is_file()]
            (output / "SHA256SUMS").write_text("\n".join(manifest) + "\n")
            (output / "COMPLETE").write_text("Lab 13 capture complete; label: host\n")

            exported = Path(directory) / "counter.json"
            export = subprocess.run(
                [sys.executable, "-O", str(EXPORTER), str(output), "--output", str(exported)],
                capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(export.returncode, 0, export.stderr)
            payload = json.loads(exported.read_text())["captures"][0]
            self.assertTrue(payload["states"]["capture_complete"])
            self.assertFalse(payload["states"]["hypothesis_supported"])
            self.assertFalse(payload["states"]["regression_gate_passed"])
            mutated = [c for c in payload["classified"] if c["config"] == "main_only"
                       and c["location"] == "in_main" and c["mode"] == "attack"]
            self.assertTrue(mutated and all(c["outcome"] == "unattributed_fault"
                                            and c["hypothesis_supported"] is False
                                            for c in mutated))

    def test_failed_build_retains_evidence_without_completion(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "failed"
            result = capture(output, "-fthis-flag-is-intentionally-invalid")
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((output / "COMPLETE").exists())
            self.assertFalse((output / "SHA256SUMS").exists())
            self.assertIn("-fthis-flag-is-intentionally-invalid",
                          (output / "build.stderr.txt").read_text())

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


EVIDENCE_DIR = ROOT / "labs/13-boundary-instrumentation/evidence"
RESULTS_FILE = ROOT / "labs/13-boundary-instrumentation/RESULTS.md"


class RecordedEvidenceTests(unittest.TestCase):
    """Checks on the committed Lab 13 evidence; no build tools required."""

    def test_recorded_evidence_integrity(self):
        files = sorted(EVIDENCE_DIR.glob("*.json"))
        self.assertTrue(files, "no committed Lab 13 evidence found")
        for path in files:
            data = json.loads(path.read_text())
            self.assertTrue(data["captures"])
            for cap in data["captures"]:
                self.assertIn(cap["environment"]["label"], ("host", "modern"))
                self.assertEqual(len(cap["observations"]), 72)
                self.assertTrue(cap["full_manifest_sha256"])
                self.assertTrue(cap["states"]["capture_complete"])
                self.assertTrue(cap["states"]["control_validity"])
                self.assertTrue(cap["states"]["hypothesis_supported"])
                finding = cap["finding"]
                self.assertTrue(finding["both_protects_main_and_lib"])
                self.assertTrue(finding["main_only_leaves_lib_unprotected"])
                self.assertTrue(finding["lib_only_leaves_main_unprotected"])
                self.assertTrue(finding["neither_protects_neither"])
                self.assertTrue(finding["bounds_check_blocks_all_configs"])
                self.assertEqual(finding["main_only_oracle_false_positives"], 1)
                self.assertEqual(finding["main_only_oracle_false_negatives"], 1)
                self.assertEqual(finding["emitted_but_not_effective_count"], 0)

    def test_results_prose_matches_evidence(self):
        results = RESULTS_FILE.read_text()
        cap = json.loads((EVIDENCE_DIR / "2026-11-19.json").read_text())["captures"][0]
        self.assertIn(
            "emitted_but_not_effective_count = %d"
            % cap["coverage"]["emitted_but_not_effective_count"],
            results,
        )
        oracle = cap["main_only_oracle"]
        self.assertIn(
            "%d of %d cells" % (oracle["misclassified_count"], len(oracle["cells"])),
            results,
        )
        counts = {}
        for row in cap["classified"]:
            counts[row["outcome"]] = counts.get(row["outcome"], 0) + 1
        for outcome, count in counts.items():
            self.assertIn("%s:%d" % (outcome, count), results)


if __name__ == "__main__":
    unittest.main()
