"""Real compiler and runtime checks for Lab 11 (CET shadow-stack: requested vs.
observed enforcement).

This lab's claim is conditional on what the environment actually provides, so the
tests assert the INVARIANTS that must hold on any x86-64 Linux, not the host's
particular activation state:

  * cet_full carries the CET ELF note; cet_none does not (emission is a build fact).
  * The uninstrumented reference reaches hijack() under the attack on every runtime
    (the overflow and layout are real; no mitigation to stop it).
  * The CET-note binary enforces (faults) ONLY where the shadow stack is actually
    active; where it is not active it behaves exactly like the uninstrumented one.
  * The capture is COMPLETE regardless of outcome, and the four states are recorded.

The decoupling test then proves, through the lab's own policy, that a shadow stack
that silently failed to enforce would be a complete capture with
hypothesis_supported False — the property the legacy collectors lack.
"""
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
SCRIPT = ROOT / "scripts" / "capture-cet.py"
EXPORTER = ROOT / "scripts" / "export-cet.py"
TOOLS = ("gcc", "make", "readelf", "objdump", "getconf")


def _load_collector():
    spec = importlib.util.spec_from_file_location("capture_cet", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(ROOT / "scripts" / "research"))
    spec.loader.exec_module(module)
    return module


def capture(output, label="host"):
    env = os.environ.copy()
    for key in ("CC", "CFLAGS", "LDFLAGS"):
        env.pop(key, None)
    return subprocess.run(
        [sys.executable, "-O", str(SCRIPT), label, str(output)],
        cwd="/tmp", env=env, capture_output=True, timeout=120,
    )


@unittest.skipUnless(all(shutil.which(tool) for tool in TOOLS), "requires Linux build tools")
class CetShadowStackTests(unittest.TestCase):
    def test_collects_activation_chain_and_records_states(self):
        with tempfile.TemporaryDirectory(prefix="cet ") as directory:
            output = Path(directory) / "host results"
            result = capture(output)
            self.assertEqual(result.returncode, 0,
                             result.stderr.decode() + result.stdout.decode())
            # COMPLETE is written on capture completeness, independent of outcome.
            self.assertTrue((output / "COMPLETE").exists())

            observations = json.loads((output / "observations.json").read_text())
            self.assertEqual(len(observations), 2 * 2 * 2 * 3)  # profile*runtime*mode*repeat

            chain = json.loads((output / "activation_chain.json").read_text())
            # cet_none must never carry a CET note (it is built -fcf-protection=none).
            # cet_full carries one only on a toolchain/CPU target that emits it; the
            # collector treats a missing note as a valid "chain breaks at emitted"
            # result (e.g. a QEMU guest without CET), so we do NOT require the note
            # here -- that would make the test stricter than the collector's own
            # contract and fail on a CET-less host. We assert only the invariant:
            # cet_full's emission must be at least as strong as cet_none's.
            self.assertFalse(chain["emitted"]["cet_none"]["cet_note_present"])
            cet_full_note = chain["emitted"]["cet_full"]["cet_note_present"]
            if not cet_full_note:
                # No CET note emittable here: the chain breaks at `emitted`, no
                # profile can activate the shadow stack. This is the VM-style
                # environment; nothing further about activation can be required.
                self.assertFalse(chain["activated"]["cet_full"]["default"])
                self.assertFalse(chain["activated"]["cet_full"]["shstk"])

            def rows_for(profile, runtime):
                return [r for r in observations if r["profile"] == profile
                        and r["runtime"] == runtime and r["mode"] == "attack"]

            def reaches(profile, runtime):
                return all(r["hijacked"] for r in rows_for(profile, runtime))

            def active(profile, runtime):
                # Per-process activation, from the tested binaries themselves.
                return chain["activated"][profile][runtime]

            # The uninstrumented reference is exploitable on every runtime: this is
            # the control that proves the overflow itself works.
            self.assertTrue(reaches("cet_none", "default"))
            self.assertTrue(reaches("cet_none", "shstk"))

            # A binary without the CET note can never have the shadow stack active,
            # even under the tunable (activation depends on emission, per process).
            self.assertFalse(active("cet_none", "default"))
            self.assertFalse(active("cet_none", "shstk"))

            # The CET-note binary enforces EXACTLY where its own process reported the
            # shadow stack active, and when it enforces the stop is a control-
            # protection fault (SEGV_CPERR), not a bare SIGSEGV. Where it never
            # activates, cet_full behaves like the reference — itself the anchor
            # finding, not a test failure. We assert the implication, true either way.
            for runtime in ("default", "shstk"):
                rows = rows_for("cet_full", runtime)
                if active("cet_full", runtime):
                    self.assertFalse(reaches("cet_full", runtime))
                    self.assertTrue(all(r["segv_cperr"] is True for r in rows),
                                    "an enforced stop must be a SEGV_CPERR fault")
                else:
                    self.assertTrue(reaches("cet_full", runtime))

            # The metadata-only inference is wrong whenever the note is present, the
            # process did NOT have the shadow stack active, and it still reached
            # hijack() — i.e. a declared-but-unenforced run.
            finding = json.loads((output / "finding.json").read_text())
            self.assertEqual(
                finding["metadata_only_inference_would_be_wrong"],
                finding["cet_full_note_present"]
                and active("cet_full", "default") is False
                and reaches("cet_full", "default"),
            )
            # Activation depends on emission: a true positive finding on this lab.
            # The collector only asserts this on a CET-capable environment
            # (shstk_environment_capable); on a host that emits no CET note at all
            # the field is False by construction, so we only check the positive
            # claim where the note is actually emittable.
            if cet_full_note:
                self.assertEqual(
                    finding["tunable_does_not_activate_shstk_without_cet_note"],
                    active("cet_none", "shstk") is False,
                )
            else:
                self.assertFalse(
                    finding["tunable_does_not_activate_shstk_without_cet_note"])

            # Metadata-only oracle: the inference rule a note-only checker applies,
            # compared to runtime truth. Each cell is self-consistent, and a cell is
            # a false positive IFF the oracle says "protected" but the runtime did
            # not stop the attack. On a CET-capable host the cet_full/default cell is
            # exactly such a false positive (note present, but inactive at runtime).
            oracle = json.loads((output / "metadata_oracle.json").read_text())
            counted_fps = 0
            for cell in oracle["cells"]:
                is_fp = (cell["metadata_only_verdict"] == "protected"
                         and cell["runtime_truth"] == "not protected")
                self.assertEqual(cell["false_positive"], is_fp,
                                 "oracle false_positive flag inconsistent: %r" % cell)
                counted_fps += int(is_fp)
            self.assertEqual(oracle["false_positive_count"], counted_fps)
            if (cet_full_note and active("cet_full", "default") is False
                    and reaches("cet_full", "default")):
                # A CET-capable environment where the shadow stack is inactive by
                # default: the note IS present, so the metadata-only rule says
                # "protected", yet the attack reaches the oracle -- a true false
                # positive, the paper's central claim. (Without the cet_full_note
                # guard this would also fire on a CET-less host, where the rule
                # correctly says "not protected" and the FP count is 0.)
                self.assertGreaterEqual(oracle["false_positive_count"], 1)
                self.assertEqual(finding["metadata_only_false_positives"],
                                 oracle["false_positive_count"])

            # The four states are recorded, and a clean capture supports its
            # hypothesis (the policy's expectation adapts to the activation state).
            states = json.loads((output / "states.json").read_text())
            self.assertTrue(states["capture_complete"])
            self.assertTrue(states["control_validity"])
            self.assertTrue(states["hypothesis_supported"])
            self.assertTrue(states["regression_gate_passed"])

            # The exporter accepts the complete capture and carries states through.
            exported = Path(directory) / "portable.json"
            export = subprocess.run(
                [sys.executable, "-O", str(EXPORTER), str(output), "--output", str(exported)],
                capture_output=True, timeout=60,
            )
            self.assertEqual(export.returncode, 0, export.stderr.decode())
            payload = json.loads(exported.read_text())
            self.assertEqual(payload["captures"][0]["states"], states)

    def test_silent_enforcement_failure_exports_end_to_end_as_counter_finding(self):
        # Codex #3: a GENUINE end-to-end counter-finding. We take a real complete
        # capture, mutate the cet_full/shstk/attack cell to a silent enforcement
        # failure (the shadow stack was active but the RET still reached hijack(),
        # no SEGV_CPERR), rebuild the capture's per-trial files, states, classified,
        # finding, SHA256SUMS and COMPLETE exactly as the collector would, and then
        # run the REAL export-cet.py over it. The legacy collectors would never have
        # written COMPLETE for such a result; here the export must succeed and carry
        # hypothesis_supported=false through unchanged.
        collector = _load_collector()
        from outcomes import annotate, capture_states  # noqa: E402

        with tempfile.TemporaryDirectory(prefix="cet cf ") as directory:
            output = Path(directory) / "host results"
            self.assertEqual(capture(output).returncode, 0)

            observations = json.loads((output / "observations.json").read_text())
            target = [r for r in observations if r["profile"] == "cet_full"
                      and r["runtime"] == "shstk" and r["mode"] == "attack"]
            self.assertTrue(target, "expected a cet_full/shstk/attack cell")

            # Mutate that cell to the silent-failure case and construct a matching
            # stderr trace: the process REPORTED the shadow stack active (0x1) yet the
            # attack still reached hijack() with no control-protection fault. Because
            # we write the trace, this is exercised on ANY host, with or without CET
            # hardware — the point is the classification/export path, not the CPU.
            for r in target:
                r["hijacked"], r["returned_safely"] = True, False
                r["returncode"], r["signal"] = 42, None
                r["shstk_active"], r["segv_cperr"] = True, None
                # Also force the environment-capability fields the expectation reads,
                # so the pre-registered outcome is BLOCK (enforcement expected) on ANY
                # host -- including one whose real build emits no CET note. Without
                # this, _environment_can_enforce would be False on a CET-less host and
                # the expectation would collapse to EFFECT, so the intended
                # counter-finding (expected BLOCK, observed effect) would not arise.
                r["cet_note_present"], r["cpu_user_shstk"] = True, True
                stem = "{profile}.{runtime}.{mode}.{repeat}".format(**r)
                (output / (stem + ".stdout.txt")).write_text(
                    "victim returned normally\nHIJACK: control-flow redirected\n")
                # stderr reports an active shadow stack but no SEGV_SI_CODE line, so
                # the exporter's cross-check derives shstk_active=True, segv_cperr=None.
                (output / (stem + ".stderr.txt")).write_text("SHSTK_STATUS=0x1\n")
                (output / (stem + ".status.json")).write_text(
                    json.dumps({"returncode": 42}) + "\n")
            (output / "observations.json").write_text(json.dumps(observations, indent=2) + "\n")

            # Recompute the derived files exactly as the collector does.
            annotated = annotate(observations, collector.LAB_POLICY)
            states = capture_states(observations, collector.LAB_POLICY,
                                    control_valid=True, capture_complete=True)
            self.assertTrue(states["capture_complete"])
            self.assertFalse(states["hypothesis_supported"],
                             "the mutated cell must break the hypothesis")
            (output / "states.json").write_text(json.dumps(states, indent=2) + "\n")
            (output / "classified.json").write_text(json.dumps(
                [{"profile": r["profile"], "runtime": r["runtime"], "mode": r["mode"],
                  "repeat": r["repeat"], "outcome": r["outcome"],
                  "hypothesis_supported": r["hypothesis_supported"]} for r in annotated],
                indent=2) + "\n")
            finding = json.loads((output / "finding.json").read_text())
            finding["hypothesis_supported"] = states["hypothesis_supported"]
            (output / "finding.json").write_text(json.dumps(finding, indent=2) + "\n")

            # Rebuild SHA256SUMS over everything except the manifest and COMPLETE,
            # then rewrite COMPLETE — the capture is complete regardless of outcome.
            import hashlib
            (output / "SHA256SUMS").unlink()
            (output / "COMPLETE").unlink()
            manifest = [hashlib.sha256(p.read_bytes()).hexdigest() + "  "
                        + str(p.relative_to(output))
                        for p in sorted(output.rglob("*")) if p.is_file()]
            (output / "SHA256SUMS").write_text("\n".join(manifest) + "\n")
            (output / "COMPLETE").write_text("Lab 11 capture complete; label: host\n")

            # The REAL exporter must accept it and carry the counter-finding through.
            exported = Path(directory) / "counter.json"
            export = subprocess.run(
                [sys.executable, "-O", str(EXPORTER), str(output), "--output", str(exported)],
                capture_output=True, timeout=60,
            )
            self.assertEqual(export.returncode, 0, export.stderr.decode())
            payload = json.loads(exported.read_text())["captures"][0]
            self.assertTrue(payload["states"]["capture_complete"])
            self.assertFalse(payload["states"]["hypothesis_supported"],
                             "the exported counter-finding must keep hypothesis_supported=false")
            self.assertFalse(payload["states"]["regression_gate_passed"])
            mutated = [c for c in payload["classified"] if c["profile"] == "cet_full"
                       and c["runtime"] == "shstk" and c["mode"] == "attack"]
            self.assertTrue(mutated and all(c["hypothesis_supported"] is False for c in mutated))


class CommittedEvidenceConsistencyTests(unittest.TestCase):
    """Bind the numbers written in RESULTS.md to the committed evidence, so the prose
    cannot drift from the data (mirrors tests/test_results_consistency.py for the
    fields that are Lab-11-specific). No build tools needed, so this runs in CI."""

    EVIDENCE = ROOT / "labs/11-cet-shadow-stack/evidence/2026-11-19.json"
    RESULTS = ROOT / "labs/11-cet-shadow-stack/RESULTS.md"

    def setUp(self):
        self.captures = json.loads(self.EVIDENCE.read_text())["captures"]
        self.results = self.RESULTS.read_text()

    def test_metadata_oracle_false_positive_count_matches_results_prose(self):
        # RESULTS.md states "1 of 4 cells is a false positive" for the host. That
        # number must equal the host capture's recorded oracle count, so the central
        # claim cannot be overstated or go stale when the evidence is regenerated.
        host = next(c for c in self.captures if c["environment"]["label"] == "host")
        fp = host["metadata_oracle"]["false_positive_count"]
        total = len(host["metadata_oracle"]["cells"])
        self.assertRegex(
            self.results, r"\b%d of %d cells is a false positive" % (fp, total),
            "RESULTS.md host false-positive prose does not match the evidence "
            "(%d of %d); update the prose or regenerate the evidence" % (fp, total))

    def test_results_name_both_recorded_environments(self):
        # The two-environment claim must name both captured environments' OS.
        labels = {c["environment"]["label"] for c in self.captures}
        self.assertEqual(labels, {"host", "modern"})
        self.assertIn("Ubuntu", self.results)
        self.assertIn("Debian", self.results)

    def test_chain_break_links_match_the_evidence(self):
        # The transferability claim names where the chain breaks per environment.
        for capture in self.captures:
            breaks_at = capture["finding"]["chain_breaks_at"]
            self.assertIn(
                breaks_at, self.results,
                "RESULTS.md does not mention the recorded chain-break link %r for %s"
                % (breaks_at, capture["environment"]["label"]))


if __name__ == "__main__":
    unittest.main()
