#!/usr/bin/env python3
"""Build and measure Lab 12; no external target is accepted.

Lab 12 measures FORTIFY coverage: when a _FORTIFY_SOURCE level is requested, which
buffer copies are ACTUALLY checked? It builds the same copy in three size-knowledge
variants (static / runtime / crosstu) at three levels (off / 2 / 3) and records,
separately and per (level, variant):

  emitted    -- whether the compiler emitted __memcpy_chk (read from the binary's
                per-function disassembly), i.e. the check is present in the code
  effective  -- whether an actual overflow is caught at run time ("buffer overflow
                detected" abort) or proceeds unchecked

so the gap between "FORTIFY requested" and "this copy is checked" is measured from
the emitted code and confirmed at run time, not inferred from the flag. A benign
in-bounds run is the baseline control. The stack protector is disabled in the
Makefile so the only thing that can abort an overflow is an effective __memcpy_chk,
isolating FORTIFY from the canary (Lab 04).

Like Lab 11, this collector writes COMPLETE on capture completeness, independent of
whether any particular cell was checked, and records the four research states via
scripts/research/outcomes.py — so a coverage counter-finding stays a complete,
exportable capture rather than a discarded one.
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

OVERFLOW_MARKER = b"buffer overflow detected"
COMPLETED_MARKER = b"completed mode="
DEST_SIZE = 32

LEVELS = ("off", "l2", "l3")          # binary suffixes, = requested FORTIFY level
BINARY_FOR_LEVEL = {"off": "fortify_off", "l2": "fortify_l2", "l3": "fortify_l3"}
VARIANTS = ("static", "runtime", "crosstu")
# The function whose memcpy each variant exercises; crosstu's copy is in sink_copy.
FUNC_FOR_VARIANT = {"static": "copy_static", "runtime": "copy_runtime",
                    "crosstu": "sink_copy"}
MODES = ("attack", "safe")            # attack overflows (n>DEST_SIZE); safe is in-bounds
REPEATS = 3
ATTACK_N = "100"                      # overflow of a 32-byte destination
SAFE_N = "16"                         # in-bounds
RUNTIME_CAP = "32"                    # runtime-variant heap capacity (matches DEST_SIZE)

# Outcome policy. For a safe (in-bounds) run the copy completes normally — a
# controlled local effect, the baseline control. For an attack (overflow):
#   - if FORTIFY checked the copy, it aborts with "buffer overflow detected"
#     (the stop signature, required as positive proof via strict_block_signal) ->
#     blocked_before_operation;
#   - if FORTIFY did NOT check it, the overflow is not stopped by the mitigation
#     under test and corrupts memory, faulting via the stack or the heap allocator
#     (SIGSEGV / malloc SIGABRT). That fault is NOT attributable to FORTIFY, so it
#     is unattributed_fault — the honest classification of "this copy was unchecked".
# A bare SIGSEGV/SIGABRT therefore never counts as a FORTIFY block.
EFFECT = "controlled_local_effect"    # safe baseline: copy completed
BLOCK = "blocked_before_operation"    # FORTIFY aborted the overflow
UNATTRIBUTED = "unattributed_fault"   # overflow unchecked by FORTIFY -> raw fault

# Pre-registered coverage: which (level, variant) cells FORTIFY is expected to check.
# static: checked from L2 (constant size). runtime: only L3 (dynamic object size).
# crosstu: never (size opaque across the TU boundary).
_EXPECT_CHECKED = {
    ("l2", "static"), ("l3", "static"),
    ("l3", "runtime"),
}


def _expectation(observation):
    if observation.get("mode") == "safe":
        return None  # baseline control, no attack hypothesis
    key = (observation.get("level"), observation.get("variant"))
    # Checked cells: FORTIFY blocks. Unchecked cells: the overflow faults without
    # FORTIFY (unattributed to the mitigation under test).
    return BLOCK if key in _EXPECT_CHECKED else UNATTRIBUTED


LAB_POLICY = LabPolicy(
    # The safe control completes (overflow_completed True) -> controlled_local_effect.
    # An attack never completes (it is either FORTIFY-blocked or it faults), so for
    # attacks the effect flag is absent and classification falls to the stop logic.
    effect_flags=["overflow_completed"],
    repair_outcome=BLOCK,
    # A block is credited to FORTIFY ONLY on the "buffer overflow detected" abort
    # (fortify_abort), proven per run. A raw SIGSEGV/malloc-SIGABRT from the
    # unguarded overflow is not FORTIFY: strict_block_signal makes it fall through
    # to unattributed_fault, never a silent block.
    block_signal=lambda o: o.get("fortify_abort") is True,
    strict_block_signal=True,
    unexpected_fault=True,
    expectation=_expectation,
)


def require(condition, message):
    if not condition:
        raise RuntimeError(str(message))


def emitted_chk(objdump_text, func):
    """Whether `func`'s disassembly calls __memcpy_chk (emitted check) or plain
    memcpy. Reads the single function body so inlining elsewhere cannot mask it."""
    marker = "<%s>:" % func
    if marker not in objdump_text:
        return None  # function not present (e.g. inlined away) — recorded as such
    body = objdump_text.split(marker, 1)[1].split("\n\n", 1)[0]
    if "__memcpy_chk" in body:
        return True
    return False


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

    def record(command, stem, **kwargs):
        (output / (stem + ".command.json")).write_text(json.dumps(command) + "\n")
        try:
            result = subprocess.run(command, capture_output=True, timeout=30, env=base_env, **kwargs)
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
    shutil.copy2(__file__, output / "capture-fortify-coverage.py")
    shutil.copy2(ROOT / "scripts/research/outcomes.py", output / "outcomes.py")
    shutil.copy2("/etc/os-release", output / "os-release.txt")
    lab = output / "12-fortify-coverage"
    shutil.copytree(ROOT / "labs/12-fortify-coverage/src", lab / "src")
    shutil.copy2(ROOT / "labs/12-fortify-coverage/Makefile", lab)
    for name, command in (("compiler", [cc, "--version"]), ("compiler-target", [cc, "-dumpmachine"]),
                          ("binutils", ["readelf", "--version"]), ("libc", ["getconf", "GNU_LIBC_VERSION"])):
        record(command, name).check_returncode()
    record(["make", "--always-make", "CC=" + cc, "CFLAGS=" + metadata["CFLAGS"],
            "LDFLAGS=" + metadata["LDFLAGS"]], "build", cwd=lab).check_returncode()

    # --- Emitted link: read __memcpy_chk presence per (level, variant) from the
    # per-function disassembly of each binary. ---
    emitted = {}
    for level in LEVELS:
        binary = BINARY_FOR_LEVEL[level]
        disas = record(["objdump", "-d", str(lab / binary)], binary + ".objdump")
        disas.check_returncode()
        text = disas.stdout.decode(errors="replace")
        emitted[level] = {variant: emitted_chk(text, FUNC_FOR_VARIANT[variant])
                          for variant in VARIANTS}

    # --- Effective link: run each cell and see whether an overflow is caught. ---
    observations = []
    big_src = "A" * 200
    for level in LEVELS:
        binary = str(lab / BINARY_FOR_LEVEL[level])
        for variant in VARIANTS:
            for mode in MODES:
                n = ATTACK_N if mode == "attack" else SAFE_N
                args = [binary, variant, n, big_src, RUNTIME_CAP]
                for repeat in range(1, REPEATS + 1):
                    stem = "{}.{}.{}.{}".format(level, variant, mode, repeat)
                    res = record(args, stem)
                    rc = res.returncode
                    out = res.stdout + res.stderr
                    fortify_abort = OVERFLOW_MARKER in out
                    completed = COMPLETED_MARKER in res.stdout
                    row = {
                        "level": level, "variant": variant, "mode": mode, "repeat": repeat,
                        "returncode": rc,
                        "signal": signal.Signals(-rc).name if rc < 0 else None,
                        # The attack effect: the overflow ran to completion unchecked.
                        # (For safe mode this is also True — a normal completion — and
                        # safe carries no hypothesis.)
                        "overflow_completed": completed,
                        # Positive proof a stop was FORTIFY's, not the raw fault.
                        "fortify_abort": fortify_abort,
                        "emitted_chk": emitted[level][variant],
                    }
                    observations.append(row)
                    (output / "observations.json").write_text(json.dumps(observations, indent=2) + "\n")

    # Determinism: each (level, variant, mode) cell must be single-valued.
    for level in LEVELS:
        for variant in VARIANTS:
            for mode in MODES:
                cell = {(r["returncode"], r["overflow_completed"], r["fortify_abort"])
                        for r in observations
                        if r["level"] == level and r["variant"] == variant and r["mode"] == mode}
                require(len(cell) == 1,
                        "cell {}/{}/{} not deterministic: {}".format(level, variant, mode, cell))

    # Control validity: every safe (in-bounds) run must complete normally, and the
    # unguarded (off) attacks must NOT abort via FORTIFY (they either complete or
    # fault for another reason) — proving the FORTIFY aborts elsewhere are FORTIFY's.
    safe_ok = all(r["overflow_completed"] and r["returncode"] == 0
                  for r in observations if r["mode"] == "safe")
    off_not_fortified = not any(r["fortify_abort"]
                                for r in observations if r["level"] == "off")
    control_valid = bool(safe_ok and off_not_fortified)

    annotated = annotate(observations, LAB_POLICY)
    states = capture_states(observations, LAB_POLICY,
                            control_valid=control_valid, capture_complete=True)

    # Coverage matrix: emitted vs. effective per (level, variant), from attack runs.
    def attack_rows(level, variant):
        return [r for r in observations if r["level"] == level
                and r["variant"] == variant and r["mode"] == "attack"]

    coverage = []
    emitted_effective_disagreements = 0
    for level in LEVELS:
        for variant in VARIANTS:
            rows = attack_rows(level, variant)
            chk = emitted[level][variant]
            effective = bool(rows) and all(r["fortify_abort"] for r in rows)
            # A chk emitted but not effective (e.g. unknown object size => pass-through)
            # is the sharpest coverage gap: present in the code, inert at run time.
            disagree = (chk is True) and not effective
            emitted_effective_disagreements += int(disagree)
            coverage.append({
                "level": level, "variant": variant,
                "emitted_chk": chk, "effective": effective,
                "emitted_but_not_effective": disagree,
            })
    (output / "coverage.json").write_text(json.dumps({
        "dest_size": DEST_SIZE,
        "cells": coverage,
        "emitted_but_not_effective_count": emitted_effective_disagreements,
    }, indent=2) + "\n")

    (output / "states.json").write_text(json.dumps(states, indent=2) + "\n")
    (output / "classified.json").write_text(json.dumps(
        [{"level": r["level"], "variant": r["variant"], "mode": r["mode"],
          "repeat": r["repeat"], "outcome": r["outcome"],
          "hypothesis_supported": r["hypothesis_supported"]} for r in annotated],
        indent=2) + "\n")

    def checked(level, variant):
        rows = attack_rows(level, variant)
        return bool(rows) and all(r["fortify_abort"] for r in rows)

    (output / "finding.json").write_text(json.dumps({
        # The coverage headline, as measured booleans.
        "static_checked_at_l2": checked("l2", "static"),
        "runtime_checked_at_l2": checked("l2", "runtime"),
        "runtime_checked_at_l3": checked("l3", "runtime"),
        "crosstu_checked_at_l3": checked("l3", "crosstu"),
        # The level-2-vs-3 coverage difference on a runtime-sized destination: the
        # same flag family leaves a copy unchecked at L2 and checked at L3.
        "runtime_coverage_differs_l2_vs_l3":
            checked("l3", "runtime") and not checked("l2", "runtime"),
        # A copy FORTIFY cannot reach even at the highest level, because the size is
        # opaque across a translation-unit boundary.
        "crosstu_never_checked":
            not checked("l2", "crosstu") and not checked("l3", "crosstu"),
        # Emitted-but-not-effective cells (chk present yet inert): 0 is the clean case.
        "emitted_but_not_effective_count": emitted_effective_disagreements,
        "control_validity": control_valid,
        "hypothesis_supported": states["hypothesis_supported"],
    }, indent=2) + "\n")

    manifest = [hashlib.sha256(path.read_bytes()).hexdigest() + "  " + str(path.relative_to(output))
                for path in sorted(output.rglob("*")) if path.is_file()]
    (output / "SHA256SUMS").write_text("\n".join(manifest) + "\n")
    (output / "COMPLETE").write_text("Lab 12 capture complete; label: " + label + "\n")


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
    print("Lab 12 captured in " + str(args.output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
