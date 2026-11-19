#!/usr/bin/env python3
"""Build and measure Lab 11; no external target is accepted.

Lab 11 measures the gap between a CET shadow stack being REQUESTED (build flag,
ELF note) and actually ENFORCED for a concrete control-flow operation at runtime.
It records each link of the activation chain separately, for two build profiles
under two runtime states:

  profiles   cet_full  (-fcf-protection=full): CET note present, endbr64 pads
             cet_none  (-fcf-protection=none): the uninstrumented reference
  runtimes   default   the shadow stack as the loader leaves it (here: inactive)
             shstk     GLIBC_TUNABLES=glibc.cpu.hwcaps=SHSTK, requesting activation
  modes      attack    full return-address overwrite -> hijack() unless stopped
             safe      non-overflowing copy -> returns normally (baseline control)

The chain recorded per (profile, runtime): requested, emitted, supported,
activated, covered, effective (see research/plan.yaml activation_chain).

CRUCIAL design difference from the Labs 04-10 collectors: this collector does NOT
gate its COMPLETE marker on the result matching an expectation. A capture is
COMPLETE when all the data was recorded, whatever the outcome. The four research
states (capture_complete / control_validity / hypothesis_supported /
regression_gate_passed) are computed from the observations via scripts/research/
outcomes.py and written to states.json. A shadow stack that silently fails to
enforce is therefore recorded as a complete capture with hypothesis_supported
false, not discarded. This is the decoupling the plan requires of new labs.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import resource
import shutil
import signal
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "research"))
from outcomes import LabPolicy, annotate, capture_states  # noqa: E402

HIJACK_MARKER = b"HIJACK: control-flow redirected\n"
SAFE_MARKER = b"main completed\n"
HIJACK_STATUS = 42
SEGV_FAULT_STATUS = 70
SEGV_CPERR = 10                    # si_code for a control-protection fault
SHSTK_TUNABLE = "glibc.cpu.hwcaps=SHSTK"

PROFILES = ("cet_full", "cet_none")
RUNTIMES = ("default", "shstk")
MODES = ("attack", "safe")
REPEATS = 3

# The lab's outcome policy, recorded natively (not retrofitted). The attack's
# "effect" is reaching hijack(). When the effect does NOT occur the shadow stack
# blocked the RET; the block is attributed to the shadow stack ONLY when the fault
# is a control-protection fault (SEGV_CPERR), observed per process, never for an
# arbitrary SIGSEGV. The safe control carries no attack hypothesis.
#
# The expectation is keyed by the OBSERVED per-process shadow-stack status
# (shstk_active), not by the runtime label. Enforcement is expected exactly where
# the tested process actually had the shadow stack active; everywhere else the
# operation is expected to reach hijack() like the uninstrumented reference. This
# is the pre-registered hypothesis; a deviation is a counter-finding, not a
# discarded capture.
EFFECT = "controlled_local_effect"
BLOCK = "blocked_before_operation"


def _environment_can_enforce(observation):
    """Whether a shadow stack is even possible for this trial's environment, read
    per observation (so one classifier run can mix a CET-capable host capture and a
    CET-incapable VM capture): the binary must carry the CET note AND the CPU must
    advertise user_shstk. Each observation records both facts."""
    return bool(observation.get("cet_note_present") and observation.get("cpu_user_shstk"))


def _expectation(observation):
    if observation.get("mode") == "safe":
        return None  # baseline control, no attack hypothesis
    if not _environment_can_enforce(observation):
        # No CET note emittable, or no CPU support: no profile can enforce, so the
        # attack is expected to reach hijack() everywhere, like the uninstrumented
        # reference. The chain breaks at emitted/supported, not activated.
        return EFFECT
    return BLOCK if observation.get("shstk_active") else EFFECT


LAB_POLICY = LabPolicy(
    # The attack effect is reaching hijack(); the safe control's normal completion
    # (returned_safely) also counts as a produced in-binary effect, so the baseline
    # reads as controlled_local_effect rather than unreachable.
    effect_flags=["hijacked", "returned_safely"],
    repair_outcome=BLOCK,
    # A block is credited to the shadow stack ONLY on a control-protection fault,
    # proven by the per-process si_code (SEGV_CPERR). strict_block_signal makes this
    # the SOLE accepted proof: a plain SIGSEGV without SEGV_CPERR is NOT attributed
    # to the shadow stack and falls through to unattributed_fault, so the strong
    # causal claim ("the RET faulted because of a shadow-stack mismatch") is never
    # asserted from an ordinary fault.
    block_signal=lambda o: o.get("segv_cperr") is True,
    strict_block_signal=True,
    expectation=_expectation,
)


def require(condition, message):
    if not condition:
        raise RuntimeError(str(message))


def main_features(cpuinfo_text):
    """CPU security features advertised in /proc/cpuinfo flags (observed support)."""
    match = re.search(r"^flags\s*:(.*)$", cpuinfo_text, re.MULTILINE)
    flags = set(match[1].split()) if match else set()
    return {name: (name in flags) for name in ("user_shstk", "ibt", "smep", "smap")}


def parse_shstk_status(stderr_text):
    """The shadow-stack status the TESTED process printed for itself
    (arch_prctl ARCH_SHSTK_STATUS). Returns True (active), False (inactive), or
    None (unavailable). This is the per-process 'activated' link, read from the
    same process whose RET is under test — not from a separate probe."""
    if "SHSTK_STATUS=unavailable" in stderr_text:
        return None
    match = re.search(r"SHSTK_STATUS=0x([0-9a-f]+)", stderr_text)
    if not match:
        return None
    return (int(match[1], 16) & 0x1) == 1


def parse_segv_cperr(stderr_text):
    """Whether the tested process's SIGSEGV was a control-protection fault
    (si_code SEGV_CPERR), the positive proof that the shadow stack caught the RET.
    Returns True/False when a fault was reported, else None (no fault)."""
    match = re.search(r"SEGV_SI_CODE=(-?\d+)", stderr_text)
    if not match:
        return None
    return int(match[1]) == SEGV_CPERR


def capture(label, output):
    require(platform.system() == "Linux" and platform.machine() == "x86_64",
            "requires x86-64 Linux")
    require(os.geteuid() != 0, "run the lab as an ordinary user, not root")
    require(not any(char in str(output) for char in "\r\n"),
            "output path cannot contain newlines")
    cc = os.environ.get("CC", "gcc")
    for tool in (cc, "make", "readelf", "objdump", "getconf"):
        require(shutil.which(tool), "required tool not found: " + tool)
    output.mkdir()  # Exclusive, including dangling symlinks.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    base_env = dict(os.environ, LC_ALL="C", SHELL="/bin/sh")

    def record(command, stem, *, extra_env=None, **kwargs):
        (output / (stem + ".command.json")).write_text(json.dumps(command) + "\n")
        env = base_env if extra_env is None else dict(base_env, **extra_env)
        try:
            result = subprocess.run(command, capture_output=True, timeout=30, env=env, **kwargs)
        except subprocess.TimeoutExpired as error:
            (output / (stem + ".stdout.txt")).write_bytes(error.stdout or b"")
            (output / (stem + ".stderr.txt")).write_bytes(error.stderr or b"")
            (output / (stem + ".timeout.json")).write_text(json.dumps({"timeout_seconds": 30}) + "\n")
            raise
        (output / (stem + ".stdout.txt")).write_bytes(result.stdout)
        (output / (stem + ".stderr.txt")).write_bytes(result.stderr)
        (output / (stem + ".status.json")).write_text(json.dumps({"returncode": result.returncode}) + "\n")
        return result

    metadata = {"schema_version": 1, "label": label, "label_is_operator_supplied": True,
                "captured_at_utc": datetime.now(timezone.utc).isoformat(),
                "platform": platform.platform(), "architecture": platform.machine(),
                "python": sys.version, "CC": cc, "CFLAGS": base_env.get("CFLAGS", "-Wall -Wextra"),
                "LDFLAGS": base_env.get("LDFLAGS", "")}
    (output / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")
    shutil.copy2(__file__, output / "capture-cet.py")
    shutil.copy2(ROOT / "scripts/research/outcomes.py", output / "outcomes.py")
    shutil.copy2("/etc/os-release", output / "os-release.txt")
    shutil.copy2("/proc/cpuinfo", output / "cpuinfo.txt")
    lab = output / "11-cet-shadow-stack"
    shutil.copytree(ROOT / "labs/11-cet-shadow-stack/src", lab / "src")
    shutil.copy2(ROOT / "labs/11-cet-shadow-stack/Makefile", lab)
    for name, command in (("compiler", [cc, "--version"]), ("compiler-target", [cc, "-dumpmachine"]),
                          ("binutils", ["readelf", "--version"]), ("libc", ["getconf", "GNU_LIBC_VERSION"])):
        record(command, name).check_returncode()
    record(["make", "--always-make", "CC=" + cc, "CFLAGS=" + metadata["CFLAGS"],
            "LDFLAGS=" + metadata["LDFLAGS"]], "build", cwd=lab).check_returncode()

    # --- Link 1-2: requested and emitted, read from the ELF of each profile. ---
    emitted = {}
    for binary in PROFILES:
        elf = record(["readelf", "-W", "-n", "-h", str(lab / binary)], binary + ".readelf")
        elf.check_returncode()
        text = elf.stdout.decode()
        require(re.search(r"Type:\s+EXEC", text), binary + " is not a non-PIE ET_EXEC")
        has_note = "SHSTK" in text and "IBT" in text
        disas = record(["objdump", "-d", str(lab / binary)], binary + ".objdump")
        disas.check_returncode()
        # Count endbr64 only in our own functions (hijack/victim/main), so libc
        # startup stubs do not mask the difference between the profiles.
        own = re.findall(r"<(?:hijack|victim|main)>:(.*?)(?=\n[0-9a-f]+ <|\Z)", disas.stdout.decode(), re.S)
        endbr_own = sum(chunk.count("endbr64") for chunk in own)
        emitted[binary] = {"cet_note_present": has_note, "endbr64_in_own_code": endbr_own}
        if binary == "cet_none":
            require(not has_note, "cet_none unexpectedly carries a CET note")
    # NOTE: we do NOT require cet_full to carry the note. On some environments
    # (e.g. a QEMU guest whose CPU model does not advertise CET, or an older
    # toolchain), -fcf-protection=full emits no CET property at all. That is not a
    # collector error: it is the activation chain breaking at the *emitted* link,
    # a legitimate transferability (RQ3) result recorded as a complete capture.

    # --- Link 3: supported, from the CPU flags. ---
    features = main_features(Path("/proc/cpuinfo").read_text())

    # Whether THIS environment can even provide a shadow stack: the CET note must be
    # emittable AND the CPU must advertise user_shstk. When it cannot, no profile can
    # enforce, every attack reaches hijack(), and the expectation (per observation,
    # via _environment_can_enforce) is EFFECT everywhere — an 'unsupported'-flavoured
    # chain break (emitted/supported), not a counter-finding.
    shstk_environment_capable = bool(
        emitted["cet_full"]["cet_note_present"] and features["user_shstk"])

    # --- Links 4-6: activated, covered, effective, measured PER PROCESS. ---
    # Each tested binary reports its OWN shadow-stack status (activated) and, on a
    # fault, its own si_code (effective, via SEGV_CPERR). There is no separate probe
    # process: the status that matters is the one in the very process whose RET is
    # under test, because shadow-stack activation is per thread/process and depends
    # on the binary's ELF CET property (a binary without the note cannot activate it,
    # even under the tunable). This directly fixes attributing one probe's status to
    # a different program.
    observations = []
    for profile in PROFILES:
        for runtime in RUNTIMES:
            extra = {"GLIBC_TUNABLES": SHSTK_TUNABLE} if runtime == "shstk" else {}
            for mode in MODES:
                n = "32" if mode == "attack" else "16"
                for repeat in range(1, REPEATS + 1):
                    stem = "{}.{}.{}.{}".format(profile, runtime, mode, repeat)
                    res = record([str(lab / profile), n], stem, extra_env=extra)
                    rc = res.returncode
                    stderr_text = res.stderr.decode(errors="replace")
                    row = {
                        "profile": profile, "runtime": runtime, "mode": mode, "repeat": repeat,
                        "returncode": rc,
                        "signal": signal.Signals(-rc).name if rc < 0 else None,
                        "hijacked": HIJACK_MARKER in res.stdout,
                        "returned_safely": SAFE_MARKER in res.stdout,
                        # The operation under test is in-binary and always exercised.
                        "covered": True,
                        # Activated: this process's own shadow-stack status.
                        "shstk_active": parse_shstk_status(stderr_text),
                        # Effective: a fault that is a control-protection fault
                        # (True), an ordinary fault (False), or no fault (None).
                        "segv_cperr": parse_segv_cperr(stderr_text),
                        "cet_note_present": emitted[profile]["cet_note_present"],
                        "cpu_user_shstk": features["user_shstk"],
                    }
                    observations.append(row)
                    (output / "observations.json").write_text(json.dumps(observations, indent=2) + "\n")

    # The per-process activation table, built FROM the observations (not a probe):
    # for each (profile, runtime) the status every tested process actually reported.
    # Non-uniform status within a cell is NOT a hard error: it is recorded (the cell
    # maps to None) and surfaces as non-determinism below, so the capture still
    # completes and exports rather than being discarded.
    activated = {}
    for profile in PROFILES:
        for runtime in RUNTIMES:
            states_seen = {r["shstk_active"] for r in observations
                           if r["profile"] == profile and r["runtime"] == runtime}
            activated.setdefault(profile, {})[runtime] = (
                states_seen.pop() if len(states_seen) == 1 else None)

    # Determinism: each (profile, runtime, mode) cell SHOULD be single-valued. A
    # divergence across repeats is a genuine reliability finding, so it is RECORDED
    # (deterministic=False, with the offending cells) rather than aborting before the
    # capture is written. A non-deterministic capture completes and exports; it
    # simply cannot be a valid control or pass the regression gate.
    nondeterministic_cells = []
    for profile in PROFILES:
        for runtime in RUNTIMES:
            for mode in MODES:
                cell = {(r["returncode"], r["hijacked"], r["shstk_active"], r["segv_cperr"])
                        for r in observations
                        if r["profile"] == profile and r["runtime"] == runtime and r["mode"] == mode}
                if len(cell) != 1:
                    nondeterministic_cells.append("%s/%s/%s" % (profile, runtime, mode))
    deterministic = not nondeterministic_cells

    # Control validity: the UNINSTRUMENTED reference must actually reach hijack()
    # under the attack (proving the overflow and the layout are real), and every
    # safe control must return normally. If these do not hold the whole capture is
    # uninterpretable; we record control_validity false rather than crash.
    ref_attack_reaches = all(
        r["hijacked"] and r["returncode"] == HIJACK_STATUS
        for r in observations if r["profile"] == "cet_none" and r["mode"] == "attack")
    safe_controls_return = all(
        r["returned_safely"] and r["returncode"] == 0
        for r in observations if r["mode"] == "safe")
    # A non-deterministic capture is not an interpretable control baseline.
    control_valid = bool(ref_attack_reaches and safe_controls_return and deterministic)

    annotated = annotate(observations, LAB_POLICY)
    states = capture_states(observations, LAB_POLICY,
                            control_valid=control_valid, capture_complete=True)

    (output / "activation_chain.json").write_text(json.dumps({
        "requested": {p: (p == "cet_full") for p in PROFILES},
        "emitted": emitted,
        "supported": features,
        "activated": activated,
    }, indent=2) + "\n")
    (output / "states.json").write_text(json.dumps(states, indent=2) + "\n")
    (output / "classified.json").write_text(json.dumps(
        [{"profile": r["profile"], "runtime": r["runtime"], "mode": r["mode"],
          "repeat": r["repeat"], "outcome": r["outcome"],
          "hypothesis_supported": r["hypothesis_supported"]} for r in annotated],
        indent=2) + "\n")

    # The headline finding, stated as measured booleans (not asserted as required).
    def reaches(profile, runtime):
        return all(r["hijacked"] for r in observations
                   if r["profile"] == profile and r["runtime"] == runtime and r["mode"] == "attack")

    def blocked_by_cperr(profile, runtime):
        rows = [r for r in observations
                if r["profile"] == profile and r["runtime"] == runtime and r["mode"] == "attack"]
        return bool(rows) and all(r["segv_cperr"] is True for r in rows)

    # Metadata-only oracle vs. runtime truth. This is the direct, reproducible
    # rebuttal of "CET note present => this operation is shadow-stack protected",
    # the inference checksec / hardening-check make from the ELF alone. We implement
    # that exact inference rule (note present AND CPU support => report "protected")
    # and compare its verdict, per (profile, runtime, mode=attack), to what actually
    # happened at runtime (was the hijack stopped by a SEGV_CPERR fault?). A cell
    # where the oracle says "protected" but the operation was NOT stopped is a FALSE
    # POSITIVE: the metadata-only claim was wrong for a running process. No external
    # tool is invoked, so the result does not depend on a specific tool version; the
    # inference rule itself is what is under test (the honest guard in the README).
    def metadata_only_says_protected(profile):
        # What a note-only checker concludes: the binary advertises CET and the CPU
        # supports it. It cannot see per-process activation, so it stops here.
        return emitted[profile]["cet_note_present"] and features["user_shstk"]

    def runtime_actually_protected(profile, runtime):
        # Ground truth: the attack did NOT reach hijack AND the stop was a control-
        # protection fault (shadow-stack catch), proven per process.
        return (not reaches(profile, runtime)) and blocked_by_cperr(profile, runtime)

    oracle_cells = []
    oracle_false_positives = 0
    for profile in PROFILES:
        for runtime in RUNTIMES:
            claimed = bool(metadata_only_says_protected(profile))
            actual = bool(runtime_actually_protected(profile, runtime))
            false_positive = claimed and not actual
            oracle_false_positives += int(false_positive)
            oracle_cells.append({
                "profile": profile, "runtime": runtime,
                "metadata_only_verdict": "protected" if claimed else "not protected",
                "runtime_truth": "protected" if actual else "not protected",
                "false_positive": false_positive,
            })
    (output / "metadata_oracle.json").write_text(json.dumps({
        "inference_rule": "CET GNU-property note present AND CPU advertises user_shstk => report protected",
        "note": "implements the metadata-only inference of checksec/hardening-check; no external tool invoked",
        "cells": oracle_cells,
        "false_positive_count": oracle_false_positives,
        "false_positive_rate": oracle_false_positives / len(oracle_cells),
    }, indent=2) + "\n")

    # Where the activation chain first breaks in THIS environment (RQ3). The chain
    # is requested -> emitted -> supported -> activated -> effective; the first
    # missing link is the environment's limiting factor.
    if not emitted["cet_full"]["cet_note_present"]:
        chain_breaks_at = "emitted"            # toolchain/target emits no CET note
    elif not features["user_shstk"]:
        chain_breaks_at = "supported"          # CPU does not advertise user_shstk
    elif activated["cet_full"]["default"] is False:
        chain_breaks_at = "activated"          # emitted+supported, but inactive at runtime
    else:
        chain_breaks_at = "effective"          # activated and enforcing

    (output / "finding.json").write_text(json.dumps({
        "cet_full_note_present": emitted["cet_full"]["cet_note_present"],
        "cpu_supports_shstk": features["user_shstk"],
        # Whether this environment can provide a shadow stack at all, and where the
        # chain breaks if not. On a CET-capable host this is True and the break is
        # "activated"; on a QEMU guest without CET it is False and the break is
        # "emitted"/"supported" — the transferability (RQ3) result.
        "shstk_environment_capable": shstk_environment_capable,
        "chain_breaks_at": chain_breaks_at,
        # Per-process activation, from the tested binaries themselves.
        "cet_full_shstk_active_default": activated["cet_full"]["default"],
        "cet_full_shstk_active_tunable": activated["cet_full"]["shstk"],
        "cet_none_shstk_active_tunable": activated["cet_none"]["shstk"],
        "cet_full_default_reaches_hijack": reaches("cet_full", "default"),
        "cet_full_shstk_reaches_hijack": reaches("cet_full", "shstk"),
        "cet_none_default_reaches_hijack": reaches("cet_none", "default"),
        # The block, proven by a control-protection fault, not a bare SIGSEGV.
        "cet_full_shstk_blocked_by_control_protection_fault": blocked_by_cperr("cet_full", "shstk"),
        # Metadata-only oracle: how many (profile, runtime) cells a note-only checker
        # would call "protected" while the operation was actually not stopped.
        "metadata_only_false_positives": oracle_false_positives,
        # Finding A (CET-capable environments only): the metadata-only inference is
        # wrong — a CET-note binary with the shadow stack inactive is exploited
        # exactly like the reference.
        "metadata_only_inference_would_be_wrong":
            emitted["cet_full"]["cet_note_present"]
            and activated["cet_full"]["default"] is False
            and reaches("cet_full", "default"),
        # Finding B (CET-capable environments only): the tunable cannot activate the
        # shadow stack for a binary without the CET note — activation depends on
        # emission, measured per process.
        "tunable_does_not_activate_shstk_without_cet_note":
            shstk_environment_capable and activated["cet_none"]["shstk"] is False,
        "deterministic": deterministic,
        "nondeterministic_cells": nondeterministic_cells,
        "control_validity": control_valid,
        "hypothesis_supported": states["hypothesis_supported"],
    }, indent=2) + "\n")

    manifest = [hashlib.sha256(path.read_bytes()).hexdigest() + "  " + str(path.relative_to(output))
                for path in sorted(output.rglob("*")) if path.is_file()]
    (output / "SHA256SUMS").write_text("\n".join(manifest) + "\n")
    # COMPLETE is written whenever the capture recorded all its data — INDEPENDENT
    # of whether the hypothesis held. A counter-finding is a complete capture.
    (output / "COMPLETE").write_text("Lab 11 capture complete; label: " + label + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("label", choices=("host", "modern"))
    parser.add_argument("output", type=lambda value: Path(value).absolute())
    args = parser.parse_args()
    try:
        capture(args.label, args.output)
    except (OSError, ValueError, RuntimeError, StopIteration, subprocess.SubprocessError) as error:
        print("Capture failed (partial evidence retained): " + str(error), file=sys.stderr)
        return 1
    print("Lab 11 captured in " + str(args.output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
