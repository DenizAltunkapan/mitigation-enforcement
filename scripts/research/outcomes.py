#!/usr/bin/env python3
"""Outcome taxonomy and the four-state research model (Phase 0).

This is the thin research layer the plan calls for (paper/plan.md Section 3,
research/plan.yaml). It does not replace the per-lab collectors; it classifies the
observations they already record, so a result can be read as data rather than only
as pass/fail, and a counter-finding stays exportable.

Pure functions only: no file or process I/O, so the logic is unit-testable and can
be reused both by a read-only classifier over committed evidence
(classify_outcomes.py) and, later, by new labs that record these fields directly.

The nine outcome categories and the four states are fixed in research/plan.yaml;
this module is their executable definition. If the two ever disagree, plan.yaml is
the pre-registered authority and this module is the bug.
"""

# The pre-registered outcome taxonomy. Exactly one applies to a trial.
OUTCOMES = (
    "blocked_before_operation",   # the invalid operation was prevented
    "detected_after_operation",   # the operation happened, then was detected/aborted
    "controlled_local_effect",    # a supplied-pointer / in-binary effect occurred
    "unattributed_fault",         # a fault not attributable to a specific guarantee
    "unsupported",                # platform/hardware does not provide the feature
    "invalid_control",            # controls/preconditions make the trial uninterpretable
    "unreachable",                # the input/check path was not reached
    "environment_failure",        # build/runtime failed for environmental reasons
    "not_executed",               # the trial did not run
)

# The four independent states (paper/plan.md 3.1). A fully recorded counter-finding
# stays exportable: capture_complete=True, hypothesis_supported=False.
STATE_FIELDS = (
    "capture_complete",
    "control_validity",
    "hypothesis_supported",
    "regression_gate_passed",
)


# Stop signatures: predicates that confirm a mechanism actually acted, so that a
# "no effect" trial is only attributed to a mitigation when its positive signal is
# present. Absence of effect alone is NOT a protection result (that was the review's
# central objection: a canary binary exiting 0 with no effect is a counter-finding,
# not a silent "detected"). Each takes an observation and returns True/False.
def aborted(o):
    """A detection/abort fault: the write happened, then a guard killed the process
    (stack canary SIGABRT, FORTIFY __printf_chk abort)."""
    return o.get("signal") == "SIGABRT" or o.get("returncode") == -6


def faulted(o):
    """A hardware/loader fault before the operation completed (NX/PIE/RELRO SIGSEGV,
    or any terminating signal that is not the detect-abort path)."""
    return o.get("signal") is not None and not aborted(o)


def clean_reject(o):
    """A non-fault, non-zero exit: a pre-operation rejection by a source-level check
    (a bounds check that returns an error code), with no effect and no crash."""
    return o.get("signal") is None and (o.get("returncode") or 0) != 0


# A stop_signature maps repair_outcome -> predicate. For a detection outcome the
# abort must be seen; for a block the stop must be a fault, a clean rejection, or a
# lab-specific positive flag (declared per policy via extra_block_ok).
STOP_SIGNATURE = {
    "detected_after_operation": aborted,
    "blocked_before_operation": lambda o: faulted(o) or clean_reject(o),
}


class LabPolicy:
    """How one lab maps a raw observation to an outcome and a hypothesis check.

    A lab names:
      effect_flags:    observation keys that, when true, mean the tested memory or
                       control-flow effect occurred (e.g. "target_reached").
      repair_outcome:  the outcome to assign when the effect did NOT occur AND the
                       mechanism's stop signature is present. Either
                       "blocked_before_operation" (prevented before the write: a
                       bounds check, a read-only GOT, a non-executable page, a
                       constant format) or "detected_after_operation" (the write
                       happened, then a guard aborted: a stack canary, FORTIFY).
      expectation(obs): returns the pre-registered expected outcome for that trial's
                        mode, so hypothesis_supported is the observed==expected test.
      block_signal(obs): optional predicate that confirms a block from a direct
                       positive flag (e.g. Lab 10 safe_input_literal, Lab 07
                       mprotect_rejected, Lab 11 a SEGV_CPERR control-protection
                       fault). By default it is OR-ed with the generic fault/clean-
                       reject signature (a positive flag OR a plain fault confirms
                       the block). With strict_block_signal=True it REPLACES the
                       generic signature, so a block is credited ONLY when the flag
                       holds: this is for labs whose stop must be proven by a
                       specific mechanism (Lab 11: a bare SIGSEGV is not a shadow-
                       stack block; only SEGV_CPERR is).
      strict_block_signal: see above; when True a fault that does not satisfy
                       block_signal is NOT a block and falls through to
                       unattributed_fault.
      unexpected_fault: when True, a terminating signal that is NOT the declared stop
                       signature is recorded as unattributed_fault instead of being
                       folded into repair_outcome.

    The essential guarantee: a "no effect" trial whose stop signature is ABSENT is
    never silently attributed to the mitigation. It becomes unattributed_fault (if it
    faulted) or unreachable (if it exited cleanly with returncode 0 and no effect) —
    both of which break the pre-registered hypothesis, so a counter-finding survives.
    """

    def __init__(self, effect_flags, repair_outcome, expectation,
                 *, block_signal=None, strict_block_signal=False, unexpected_fault=True):
        # repair_outcome is either a fixed outcome string or a callable
        # (observation) -> outcome, for labs whose stop kind depends on the binary
        # variant (e.g. Lab 05: a canary detects after the write, PIE blocks before).
        if not callable(repair_outcome):
            assert repair_outcome in OUTCOMES
        if strict_block_signal:
            assert block_signal is not None, "strict_block_signal needs a block_signal"
        self.effect_flags = tuple(effect_flags)
        self._repair_outcome = repair_outcome
        self.expectation = expectation
        self.block_signal = block_signal
        self.strict_block_signal = strict_block_signal
        self.unexpected_fault = unexpected_fault

    def repair_outcome_for(self, observation):
        value = self._repair_outcome(observation) if callable(self._repair_outcome) \
            else self._repair_outcome
        assert value in OUTCOMES
        return value

    def stop_confirmed(self, observation):
        """True iff the declared repair_outcome's stop signature is present for this
        observation (its positive signal, not merely 'no effect')."""
        outcome = self.repair_outcome_for(observation)
        if outcome == "blocked_before_operation" and self.block_signal:
            if self.block_signal(observation):
                return True
            if self.strict_block_signal:
                # The only accepted proof of this block is block_signal, which did
                # not hold: do NOT fall back to the generic fault signature.
                return False
        signature = STOP_SIGNATURE.get(outcome)
        return bool(signature and signature(observation))


def _effect_occurred(observation, policy):
    return any(bool(observation.get(flag)) for flag in policy.effect_flags)


def classify(observation, policy):
    """Map one observation to exactly one outcome category.

    Generic across labs: it reads the common fields (returncode, signal), the lab's
    declared effect flags, and the lab's declared stop signature. It never inspects
    raw stdout/stderr, so it is stable across toolchains (the Lab 10 glibc wording
    difference, for instance, does not change the classification).

    Branches:
      - the trial did not run                           -> not_executed
      - the tested effect occurred                      -> controlled_local_effect
      - no effect, and the mechanism's stop signature
        is present (the POSITIVE signal, not just the
        absence of effect)                              -> repair_outcome
      - no effect, a terminating signal, but NOT the
        declared stop signature                         -> unattributed_fault
      - no effect, clean exit 0, no attributable stop   -> unreachable

    The last two branches are what make a counter-finding survive: a mitigation that
    was expected to stop the operation but produced neither its stop signature nor
    the effect is classified against the hypothesis, never silently as "it worked".
    """
    rc = observation.get("returncode")
    if rc is None:
        return "not_executed"
    if _effect_occurred(observation, policy):
        # The tested effect was produced (oracle reached, local variable written).
        # A controlled local effect, not code execution.
        return "controlled_local_effect"
    # No effect was observed. Attribute the stop to the mitigation ONLY when its
    # declared positive signature is present.
    if policy.stop_confirmed(observation):
        return policy.repair_outcome_for(observation)
    # No effect, but the declared stop signature is absent. Do not credit the
    # mitigation. A terminating signal we cannot attribute is an unattributed fault;
    # a clean exit with no effect means the tested path was never reached.
    if observation.get("signal") is not None and policy.unexpected_fault:
        return "unattributed_fault"
    return "unreachable"


def hypothesis_supported(observation, policy):
    """True iff the observed outcome equals the pre-registered expectation for its
    mode. A False here with capture_complete True is a recorded counter-finding."""
    expected = policy.expectation(observation)
    if expected is None:
        return None  # no pre-registered expectation for this mode
    return classify(observation, policy) == expected


def controls_held(observations, policy):
    """Whether the capture's CONTROLS behaved as controls, independent of whether the
    mitigation hypothesis held. A control mode (one with no attack expectation) must
    either reproduce its baseline effect or be a clean non-crashing run; a control
    that itself faulted means the harness, not the mitigation, stopped the trial, and
    the attack trials beside it are then uninterpretable. This is the regression
    precondition (plan.yaml: controls make the trial interpretable), computed
    separately from hypothesis_supported so the two states are not the same test."""
    control_rows = [o for o in observations if policy.expectation(o) is None]
    if not control_rows:
        return True  # no declared controls in this capture; nothing to invalidate
    # Outcomes that make a control uninterpretable and therefore invalidate the
    # capture. This includes `unreachable` (e.g. a safe run that exited 0 without
    # its completion marker) -- the case a looser "did not crash" check would wrongly
    # admit, and the one the collectors reject via their strict control
    # preconditions. It deliberately does NOT include `blocked_before_operation` or
    # `detected_after_operation`, because a negative control (a length-matched
    # padding run with no crafted address) is SUPPOSED to be stopped, not to produce
    # the effect; rejecting those would break a legitimate control (e.g. Lab 05's
    # `padding`).
    invalidating = ("unattributed_fault", "environment_failure",
                    "not_executed", "unreachable")
    for o in control_rows:
        if classify(o, policy) in invalidating:
            return False
    return True


def capture_states(observations, policy, *, control_valid, capture_complete):
    """Compute the four states for a whole capture.

    capture_complete is supplied by the caller (the collector knows whether all data
    was recorded, independent of outcome). The other three are derived from the
    classified observations. control_valid is an optional caller override: when the
    collector already knows preconditions failed it passes False; otherwise the
    control modes in the capture are inspected directly (controls_held), so
    control_validity is not an unconditional True.

    The four states are deliberately independent:
      - capture_complete:      all data recorded (caller).
      - control_validity:      the controls behaved as controls (derived) AND the
                               caller did not veto it.
      - hypothesis_supported:  every attack/mitigation trial matched its expectation.
      - regression_gate_passed: the capture is usable as a CI regression gate, i.e.
                               controls valid AND hypothesis held. A counter-finding
                               (hypothesis False) is still capture_complete; it simply
                               must not pass the regression gate.
    """
    supported = [hypothesis_supported(o, policy) for o in observations]
    known = [s for s in supported if s is not None]
    controls_valid = bool(control_valid) and controls_held(observations, policy)
    hypothesis_ok = bool(known) and all(known)
    return {
        "capture_complete": bool(capture_complete),
        "control_validity": controls_valid,
        "hypothesis_supported": hypothesis_ok,
        "regression_gate_passed": hypothesis_ok and controls_valid,
    }


def annotate(observations, policy):
    """Return observations with an added 'outcome' and 'hypothesis_supported' per
    row, without mutating the inputs."""
    out = []
    for o in observations:
        out.append(dict(
            o,
            outcome=classify(o, policy),
            hypothesis_supported=hypothesis_supported(o, policy),
        ))
    return out
