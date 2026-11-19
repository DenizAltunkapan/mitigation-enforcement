#!/usr/bin/env python3
"""Classify committed lab evidence into the pre-registered outcome taxonomy.

Read-only Phase 0 tool (paper/plan.md 3.3, research/plan.yaml). It reads each
lab's committed portable evidence JSON, maps every observation to one of the nine
outcome categories, and reports the four research states per capture
(capture_complete / control_validity / hypothesis_supported /
regression_gate_passed). It does not build, run, re-measure, or modify anything.

Its purpose is to express the existing labs in the research vocabulary without the
risky rewrite of seven deterministic collectors, and to give new labs (11, 14, ...)
a ready classification library (outcomes.py) to record these fields directly.

    python3 scripts/research/classify_outcomes.py            # table for all labs
    python3 scripts/research/classify_outcomes.py --json     # machine-readable
    python3 scripts/research/classify_outcomes.py --lab 09   # one lab

The committed PILOT captures (recorded concurrently with pre-registration, not
provably after it — see research/plan.yaml scope_v1) happen to pass, so for them
hypothesis_supported is True. That is NOT assumed: the classifier credits a
mitigation only when its mechanism-specific stop signature is present (an abort for
a canary/FORTIFY detection, a fault or clean rejection for a block, or a positive
flag such as safe_input_literal), never for mere absence of effect. A capture in
which a mitigation silently failed to fire would surface here as a counter-finding
(hypothesis_supported=False) that is still a complete capture. The value of the
tool is that this makes such a finding legible as data rather than a lost capture,
and it checks the taxonomy mapping is total and unambiguous. Note the scope limit:
the legacy collectors still gate their COMPLETE marker on the expected result, so a
live counter-finding is preserved by this research layer, not yet by the collectors
themselves (new labs record the four states directly; see paper/plan.md Section 8).
"""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from outcomes import LabPolicy, annotate, capture_states  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]

# Each lab's policy. expectation(obs) returns the pre-registered expected outcome
# for that trial's mode; the classifier's job is to reproduce it from raw fields.
EFFECT = "controlled_local_effect"
BLOCK = "blocked_before_operation"
DETECT = "detected_after_operation"


def _expect(mapping):
    """Build an expectation(obs) keyed by mode. A mode mapped to None (e.g. a
    normal-function 'safe' control) has no attack/mitigation hypothesis."""
    return lambda o: mapping.get(o.get("mode"))


# Modes that are controls, not attack/mitigation trials, and so carry no
# attack hypothesis: a normal-function run and a length-matched negative control.
CONTROL_MODES = {"safe", "padding"}


def _expect_by(key, mapping):
    """Build an expectation(obs) keyed by one observation field (e.g. 'binary')
    for labs whose outcome depends on the binary variant, not just the mode.
    Control modes (safe/padding) carry no hypothesis (None)."""
    def expectation(o):
        if o.get("mode") in CONTROL_MODES:
            return None
        return mapping.get(o.get(key))
    return expectation


LAB_POLICIES = {
    "04-stack-canary": LabPolicy(
        # The "effect" here is the copy running to completion (returned_from_copy):
        # for the safe control that is the expected baseline; for an overflow it is
        # what the mitigation must prevent. The three binaries then differ on the
        # overflow: the unprotected one crashes with an unattributed SIGSEGV (the
        # demonstration that, without a guard, the overflow is simply memory-unsafe
        # — NOT a protection result); the canary aborts AFTER the write (SIGABRT,
        # detection); the bounds-checked fix rejects cleanly before the write (block).
        effect_flags=["returned_from_copy"],
        repair_outcome=lambda o: {
            "stack_canary": DETECT,        # canary aborts after the write
            "stack_fixed": BLOCK,          # bounds check rejects before the write
        }.get(o.get("binary"), "unattributed_fault"),  # unprotected: no guard to credit
        expectation=_expect_by("binary", {
            "stack_unprotected": "unattributed_fault",  # no guard: the overflow faults
            "stack_canary": DETECT,                      # canary aborts after the write
            "stack_fixed": BLOCK,                        # bounds check rejects first
        }),
    ),
    "05-return-address-overwrite": LabPolicy(
        # The attack effect is reaching the oracle; the safe control's completed copy
        # (returned_from_copy) also counts as a produced local effect, so the control
        # reads as controlled_local_effect rather than unreachable.
        effect_flags=["target_reached", "returned_from_copy"],
        # The stop kind depends on the binary variant: the canary detects after the
        # write; PIE+ASLR and the bounds-check fix block before reaching the target.
        repair_outcome=lambda o: DETECT if o.get("binary") == "overwrite_canary" else BLOCK,
        expectation=_expect_by("binary", {
            "overwrite_plain": EFFECT,     # attack reaches the oracle
            "overwrite_canary": DETECT,    # canary aborts after the write
            "overwrite_pie": BLOCK,        # static address faults under ASLR
            "overwrite_fixed": BLOCK,      # bounds check rejects before the write
        }),
    ),
    "06-pie-leak-bypass": LabPolicy(
        effect_flags=["target_reached"],
        repair_outcome=BLOCK,
        expectation=_expect({"bypass": EFFECT, "stale": BLOCK, "fixed": BLOCK}),
    ),
    "07-execution-permission": LabPolicy(
        effect_flags=["marker_printed"],  # the copied oracle ran
        repair_outcome=BLOCK,  # NX faults before the bytes execute
        # A block is confirmed by the SIGSEGV on the non-executable page, or by an
        # explicit mprotect refusal; "no marker" alone is not credited.
        block_signal=lambda o: bool(o.get("mprotect_rejected")),
        expectation=_expect({"rw": BLOCK, "rx": EFFECT, "rwx": EFFECT}),
    ),
    "08-code-reuse-chain": LabPolicy(
        effect_flags=["target_reached"],
        repair_outcome=BLOCK,  # bounds check stops the overflow
        expectation=_expect({"chain": EFFECT, "partial": EFFECT, "fixed": BLOCK}),
    ),
    "09-relro-got": LabPolicy(
        effect_flags=["target_reached"],
        repair_outcome=BLOCK,  # full RELRO maps the GOT read-only -> fault before call
        expectation=_expect({"partial": EFFECT, "full": BLOCK}),
    ),
    "10-format-string": LabPolicy(
        effect_flags=["marker_leaked", "target_written"],
        # FORTIFY aborts AFTER detecting the %n write (SIGABRT) -> detection; the
        # constant-format fix rejects before any write and exits cleanly (rc 0) with
        # safe_input_literal set -> a block confirmed by that flag, not by a fault.
        repair_outcome=lambda o: DETECT if o.get("mode") == "fortify" else BLOCK,
        block_signal=lambda o: bool(o.get("safe_input_literal")),
        expectation=_expect({"leak": EFFECT, "write": EFFECT, "fortify": DETECT, "fixed": BLOCK}),
    ),
}


def _collector_policy(collector_filename):
    """Labs 11-13 record the four states natively, so their policy lives in the
    collector as the single source of truth. Import LAB_POLICY from the collector
    rather than restating it, so the unified report cannot drift from the
    capture-time classification."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        collector_filename.replace("-", "_").replace(".py", ""),
        ROOT / "scripts" / collector_filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.LAB_POLICY


for _lab, _collector in (("11-cet-shadow-stack", "capture-cet.py"),
                         ("12-fortify-coverage", "capture-fortify-coverage.py"),
                         ("13-boundary-instrumentation", "capture-boundary.py")):
    try:
        LAB_POLICIES[_lab] = _collector_policy(_collector)
    except (OSError, ImportError, AttributeError):
        pass  # Lab not present; the classifier still runs over the other labs.


def lab_dir(lab):
    return ROOT / "labs" / lab


def evidence_path(lab):
    files = sorted(lab_dir(lab).glob("evidence/*.json"))
    if not files:
        raise FileNotFoundError("no evidence for " + lab)
    return files[-1]  # the latest dated evidence


def classify_lab(lab, policy):
    data = json.loads(evidence_path(lab).read_text())
    result = {"lab": lab, "captures": []}
    for capture in data["captures"]:
        observations = capture["observations"]
        annotated = annotate(observations, policy)
        # capture_complete is True by construction for committed evidence (it carries
        # the COMPLETE marker: all data was recorded). control_validity and
        # hypothesis_supported are NOT assumed — they are derived from the classified
        # observations (control_valid=True here only means "the caller does not veto
        # it"; controls_held still inspects the control modes). A future counter-
        # finding in the committed evidence would surface here as these states going
        # False without any change to this call.
        states = capture_states(
            observations, policy, control_valid=True, capture_complete=True,
        )
        counts = {}
        for row in annotated:
            counts[row["outcome"]] = counts.get(row["outcome"], 0) + 1
        cflags = capture["environment"].get("CFLAGS", "")
        opt = next((tok for tok in cflags.split() if tok.startswith("-O")), "")
        result["captures"].append({
            "environment": capture["environment"]["label"],
            "optimization": opt,
            "n": len(observations),
            "outcome_counts": counts,
            "states": states,
            "observations": [
                {"mode": r.get("mode"), "repeat": r.get("repeat"),
                 "outcome": r["outcome"], "hypothesis_supported": r["hypothesis_supported"]}
                for r in annotated
            ],
        })
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lab", help="classify only this lab dir name prefix, e.g. 09")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args()

    labs = sorted(LAB_POLICIES)
    if args.lab:
        labs = [name for name in labs if name.startswith(args.lab)]
        if not labs:
            parser.error("no lab matches %r" % args.lab)

    results = [classify_lab(lab, LAB_POLICIES[lab]) for lab in labs]

    if args.json:
        print(json.dumps(results, indent=2))
        return 0

    all_supported = True
    for result in results:
        print("== Lab %s ==" % result["lab"])
        for cap in result["captures"]:
            states = cap["states"]
            flags = " ".join("%s=%s" % (k[0], "T" if states[k] else "F")
                             for k in ("capture_complete", "control_validity",
                                       "hypothesis_supported", "regression_gate_passed"))
            counts = ", ".join("%s:%d" % (k, v) for k, v in sorted(cap["outcome_counts"].items()))
            env_label = cap["environment"] + (" " + cap["optimization"] if cap["optimization"] else "")
            print("  %-11s n=%-2d [%s]  %s" % (env_label, cap["n"], flags, counts))
            if not states["hypothesis_supported"]:
                all_supported = False
    print("\nAll committed PILOT captures support their pre-registered hypothesis "
          "(exploratory, not a confirmatory dataset; see research/plan.yaml)."
          if all_supported else
          "\nAt least one capture is a recorded counter-finding (hypothesis_supported=False).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
