"""Tests for the Phase 0 research layer: outcome taxonomy and four-state model.

These are pure-logic tests (no build tools), plus an integration check that the
read-only classifier maps every committed observation and that the recorded
captures support their pre-registered hypothesis. A future counter-finding would
show here as hypothesis_supported=False without breaking the classification.
"""
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "research"))

import outcomes  # noqa: E402
from outcomes import LabPolicy, classify, annotate, capture_states, OUTCOMES, STATE_FIELDS  # noqa: E402


def obs(**kw):
    kw.setdefault("mode", "attack")
    return kw


class ClassifyTests(unittest.TestCase):
    def setUp(self):
        # A mitigation whose stop is a fault (RELRO/NX/PIE style).
        self.block = LabPolicy(
            effect_flags=["reached"], repair_outcome="blocked_before_operation",
            expectation=lambda o: None,
        )
        # A mitigation that detects after the write (canary style).
        self.detect = LabPolicy(
            effect_flags=["reached"], repair_outcome="detected_after_operation",
            expectation=lambda o: None,
        )

    def test_not_executed_when_no_returncode(self):
        self.assertEqual(classify(obs(returncode=None), self.block), "not_executed")
        self.assertEqual(classify(obs(), self.block), "not_executed")

    def test_effect_is_controlled_local_effect(self):
        self.assertEqual(
            classify(obs(returncode=42, signal=None, reached=True), self.block),
            "controlled_local_effect",
        )

    def test_fault_without_effect_is_block_when_signature_matches(self):
        # A block's stop signature is a fault (or a clean reject). SIGSEGV qualifies.
        self.assertEqual(
            classify(obs(returncode=-11, signal="SIGSEGV", reached=False), self.block),
            "blocked_before_operation",
        )

    def test_clean_reject_without_effect_is_block(self):
        # A bounds-check rejection: exits non-zero, no fault, no effect.
        self.assertEqual(
            classify(obs(returncode=2, signal=None, reached=False), self.block),
            "blocked_before_operation",
        )

    def test_canary_fault_is_detected_after_operation(self):
        self.assertEqual(
            classify(obs(returncode=-6, signal="SIGABRT", reached=False), self.detect),
            "detected_after_operation",
        )

    def test_block_requires_its_signature_not_mere_absence_of_effect(self):
        # The central review point: a block-expecting mitigation that exits cleanly
        # with returncode 0 and no effect produced NEITHER its stop signature nor the
        # effect. It must NOT be credited as blocked; it is a counter-finding.
        self.assertEqual(
            classify(obs(returncode=0, signal=None, reached=False), self.block),
            "unreachable",
        )

    def test_detect_requires_abort_not_clean_exit(self):
        # A canary that did not abort (clean exit, no effect) is not a detection.
        self.assertEqual(
            classify(obs(returncode=0, signal=None, reached=False), self.detect),
            "unreachable",
        )
        # A SIGSEGV is a fault, not the canary's abort signature -> unattributed.
        self.assertEqual(
            classify(obs(returncode=-11, signal="SIGSEGV", reached=False), self.detect),
            "unattributed_fault",
        )

    def test_block_signal_flag_confirms_a_clean_block(self):
        # Lab 10 'fixed' style: rc 0, no effect, but a positive flag proves the block
        # (the input was treated as a literal format), so it is a block, not unreached.
        policy = LabPolicy(
            effect_flags=["reached"], repair_outcome="blocked_before_operation",
            expectation=lambda o: None,
            block_signal=lambda o: bool(o.get("safe_literal")),
        )
        self.assertEqual(
            classify(obs(returncode=0, signal=None, reached=False, safe_literal=True), policy),
            "blocked_before_operation",
        )

    def test_fault_not_matching_signature_is_unattributed(self):
        # A fault where the lab expects a clean rejection (no fault signature) and the
        # fault is not the declared stop -> unattributed_fault, never a silent block.
        policy = LabPolicy(
            effect_flags=["reached"],
            repair_outcome="unattributed_fault",  # this binary has no mitigation to credit
            expectation=lambda o: None,
        )
        self.assertEqual(
            classify(obs(returncode=-11, signal="SIGSEGV", reached=False), policy),
            "unattributed_fault",
        )

    def test_per_observation_repair_outcome(self):
        # Lab 05 style: the stop kind depends on the binary variant.
        policy = LabPolicy(
            effect_flags=["reached"],
            repair_outcome=lambda o: "detected_after_operation"
            if o.get("binary") == "canary" else "blocked_before_operation",
            expectation=lambda o: None,
        )
        self.assertEqual(
            classify(obs(returncode=-6, signal="SIGABRT", reached=False, binary="canary"), policy),
            "detected_after_operation",
        )
        self.assertEqual(
            classify(obs(returncode=-11, signal="SIGSEGV", reached=False, binary="pie"), policy),
            "blocked_before_operation",
        )

    def test_every_classification_is_in_the_taxonomy(self):
        for observation in (
            obs(returncode=None), obs(returncode=42, reached=True),
            obs(returncode=-11, signal="SIGSEGV", reached=False),
            obs(returncode=2, signal=None, reached=False),
            obs(returncode=0, signal=None, reached=False),   # clean, no effect
            obs(returncode=-6, signal="SIGABRT", reached=False),
        ):
            self.assertIn(classify(observation, self.block), OUTCOMES)


class StateModelTests(unittest.TestCase):
    def test_counter_finding_stays_complete(self):
        # A fully recorded capture whose result contradicts the hypothesis must
        # report capture_complete True and hypothesis_supported False.
        policy = LabPolicy(
            effect_flags=["reached"], repair_outcome="blocked_before_operation",
            expectation=lambda o: "controlled_local_effect",  # we expected the effect
        )
        observations = [obs(returncode=-11, signal="SIGSEGV", reached=False)]  # but it was blocked
        states = capture_states(observations, policy, control_valid=True, capture_complete=True)
        self.assertTrue(states["capture_complete"])
        self.assertFalse(states["hypothesis_supported"])
        self.assertFalse(states["regression_gate_passed"])

    def test_supported_hypothesis_passes_gate(self):
        policy = LabPolicy(
            effect_flags=["reached"], repair_outcome="blocked_before_operation",
            expectation=lambda o: "blocked_before_operation",
        )
        observations = [obs(returncode=-11, signal="SIGSEGV", reached=False)]
        states = capture_states(observations, policy, control_valid=True, capture_complete=True)
        self.assertTrue(all(states[f] for f in STATE_FIELDS))

    def test_invalid_control_fails_gate_even_if_hypothesis_holds(self):
        policy = LabPolicy(
            effect_flags=["reached"], repair_outcome="blocked_before_operation",
            expectation=lambda o: "blocked_before_operation",
        )
        observations = [obs(returncode=-11, signal="SIGSEGV", reached=False)]
        states = capture_states(observations, policy, control_valid=False, capture_complete=True)
        self.assertFalse(states["regression_gate_passed"])

    def test_annotate_does_not_mutate(self):
        policy = LabPolicy(effect_flags=["reached"], repair_outcome="blocked_before_operation",
                           expectation=lambda o: None)
        original = obs(returncode=42, reached=True)
        before = dict(original)
        annotated = annotate([original], policy)
        self.assertEqual(original, before)
        self.assertIn("outcome", annotated[0])
        self.assertIn("hypothesis_supported", annotated[0])


class ClassifierIntegrationTests(unittest.TestCase):
    def test_classifier_runs_and_all_hypotheses_hold(self):
        # The read-only classifier over committed evidence must run cleanly, map
        # every observation to a taxonomy category, and — because committed
        # evidence encodes passing results — support every pre-registered
        # hypothesis. This binds the classifier to the real evidence.
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/research/classify_outcomes.py"), "--json"],
            capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertTrue(data, "classifier produced no labs")
        for lab in data:
            for capture in lab["captures"]:
                for row in capture["observations"]:
                    self.assertIn(row["outcome"], OUTCOMES,
                                  "%s: outcome not in taxonomy" % lab["lab"])
                self.assertTrue(
                    capture["states"]["hypothesis_supported"],
                    "%s/%s: committed evidence should support its hypothesis"
                    % (lab["lab"], capture["environment"]),
                )

    def test_silent_mitigation_failure_in_real_evidence_is_a_counter_finding(self):
        # End-to-end over the REAL evidence file, through the real policy: take Lab
        # 09's committed full-RELRO observation (a block, SIGSEGV, target not reached)
        # and mutate it to the reviewer's case — the mitigation silently did NOT fire:
        # clean exit 0, GOT call not redirected, no fault. The classifier must record
        # this as a counter-finding (hypothesis_supported False) that is still a
        # complete capture, NOT silently credit the mitigation. This exercises the
        # actual evidence shape and the actual LAB_POLICIES, not a synthetic object.
        import outcomes  # noqa
        from classify_outcomes import LAB_POLICIES, evidence_path
        policy = LAB_POLICIES["09-relro-got"]
        data = json.loads(evidence_path("09-relro-got").read_text())
        observations = [dict(o) for o in data["captures"][0]["observations"]]
        full_rows = [o for o in observations if o.get("binary") == "got_full"]
        self.assertTrue(full_rows, "expected a full-RELRO observation in real evidence")
        # As recorded, the real row is a genuine block and supports the hypothesis.
        self.assertEqual(classify(full_rows[0], policy), "blocked_before_operation")
        self.assertTrue(capture_states(
            full_rows, policy, control_valid=True, capture_complete=True,
        )["hypothesis_supported"])
        # Now simulate the silent failure on every full-RELRO row.
        for row in full_rows:
            row["returncode"], row["signal"], row["target_reached"] = 0, None, False
        self.assertEqual(classify(full_rows[0], policy), "unreachable")
        states = capture_states(
            full_rows, policy, control_valid=True, capture_complete=True,
        )
        self.assertTrue(states["capture_complete"],
                        "a silent-failure capture is still complete data")
        self.assertFalse(states["hypothesis_supported"],
                         "a mitigation that did not fire must not support its hypothesis")
        self.assertFalse(states["regression_gate_passed"])


if __name__ == "__main__":
    unittest.main()
