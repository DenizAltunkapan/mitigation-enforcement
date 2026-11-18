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


class LabPolicy:
    """How one lab maps a raw observation to an outcome and a hypothesis check.

    A lab names:
      effect_flags:    observation keys that, when true, mean the tested memory or
                       control-flow effect occurred (e.g. "target_reached").
      repair_outcome:  the outcome to assign when the effect did NOT occur, i.e. a
                       mitigation or repair acted. Either "blocked_before_operation"
                       (prevented before the write: a bounds check, a read-only
                       GOT, a non-executable page, a constant format) or
                       "detected_after_operation" (the write happened, then a guard
                       aborted: a stack canary).
      expectation(obs): returns the pre-registered expected outcome for that trial's
                        mode, so hypothesis_supported is the observed==expected test.
      fault_is_mitigation: True when a fault IS how this lab's stop manifests
                       (RELRO/NX/PIE faults, a canary aborts). False when the lab's
                       no-effect stop should be a clean rejection, so a fault is not
                       the mitigation acting.
      unexpected_fault: when True, a fault that is not the mitigation
                       (fault_is_mitigation False) is recorded as unattributed_fault
                       rather than silently folded into repair_outcome.
    """

    def __init__(self, effect_flags, repair_outcome, expectation,
                 *, fault_is_mitigation=True, unexpected_fault=False):
        # repair_outcome is either a fixed outcome string or a callable
        # (observation) -> outcome, for labs whose stop kind depends on the binary
        # variant (e.g. Lab 05: a canary detects after the write, PIE blocks before).
        if not callable(repair_outcome):
            assert repair_outcome in OUTCOMES
        self.effect_flags = tuple(effect_flags)
        self._repair_outcome = repair_outcome
        self.expectation = expectation
        self.fault_is_mitigation = fault_is_mitigation
        self.unexpected_fault = unexpected_fault

    def repair_outcome_for(self, observation):
        value = self._repair_outcome(observation) if callable(self._repair_outcome) \
            else self._repair_outcome
        assert value in OUTCOMES
        return value


def _effect_occurred(observation, policy):
    return any(bool(observation.get(flag)) for flag in policy.effect_flags)


def classify(observation, policy):
    """Map one observation to exactly one outcome category.

    Generic across labs: it reads the common fields (returncode, signal) and the
    lab's declared effect flags. It never inspects raw stdout/stderr, so it is
    stable across toolchains (the Lab 10 glibc wording difference, for instance,
    does not change the classification).

    The logic has three branches:
      - the trial did not run                         -> not_executed
      - the tested effect occurred                    -> controlled_local_effect
      - the effect did NOT occur: the mitigation or
        repair acted, so the lab's declared
        repair_outcome applies (either a clean
        pre-write rejection or a post-write abort);
        policy.unexpected_fault flags a fault that
        the lab does not attribute to its mitigation  -> repair_outcome | unattributed_fault
    """
    rc = observation.get("returncode")
    if rc is None:
        return "not_executed"
    if _effect_occurred(observation, policy):
        # The tested effect was produced (oracle reached, local variable written).
        # A controlled local effect, not code execution.
        return "controlled_local_effect"
    # No effect: the mitigation/repair acted. The lab declares what that means for
    # its design — a pre-write block, or a post-write detection/abort — and both
    # are reached whether the stop is a clean exit or a fault. A lab may also mark
    # a fault it cannot attribute to its mitigation as unattributed.
    faulted = observation.get("signal") is not None
    if faulted and policy.unexpected_fault and not policy.fault_is_mitigation:
        return "unattributed_fault"
    return policy.repair_outcome_for(observation)


def hypothesis_supported(observation, policy):
    """True iff the observed outcome equals the pre-registered expectation for its
    mode. A False here with capture_complete True is a recorded counter-finding."""
    expected = policy.expectation(observation)
    if expected is None:
        return None  # no pre-registered expectation for this mode
    return classify(observation, policy) == expected


def capture_states(observations, policy, *, control_valid, capture_complete):
    """Compute the four states for a whole capture.

    control_valid and capture_complete are supplied by the caller (the collector
    knows whether its preconditions held and whether all data was recorded). The
    other two are derived from the classified observations.
    """
    supported = [hypothesis_supported(o, policy) for o in observations]
    known = [s for s in supported if s is not None]
    return {
        "capture_complete": bool(capture_complete),
        "control_validity": bool(control_valid),
        "hypothesis_supported": bool(known) and all(known),
        "regression_gate_passed": bool(known) and all(known) and bool(control_valid),
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
