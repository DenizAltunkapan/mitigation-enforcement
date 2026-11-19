#!/usr/bin/env python3
"""Build and measure Lab 13 (partial instrumentation across a shared-library
boundary); no external target is accepted.

Lab 13 builds a main executable and a linked shared library across the 2x2
stack-protector matrix (neither / main_only / lib_only / both) and exercises
the same 32-byte linear stack copy in both components (in_main / in_lib) under
three modes (safe / attack / fixed), three repeats each (72 trials).

Per (config, location) the collector records:
  - emitted   : whether __stack_chk_fail is emitted in copy_in_main (main) and
                copy_in_lib (lib), read from per-function objdump disassembly
  - effective : whether an overflow triggers the stack-protector stop signature
                ("*** stack smashing detected ***", SIGABRT) at run time
  - main_only_oracle : what a naive executable-only checker (inspecting only
                the main binary's ELF metadata, ignoring linked libraries)
                would infer vs. runtime truth — measuring both false positives
                (main_only/in_lib) and false negatives (lib_only/in_lib).

Like Labs 11 and 12, this collector writes COMPLETE on capture completeness,
independent of outcome, and records the four research states via outcomes.py.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import shutil
import signal
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "research"))
from outcomes import LabPolicy, annotate, capture_states  # noqa: E402

CANARY_MARKER = b"stack smashing detected"
REJECTED_MARKER = b"rejected: input exceeds buffer capacity"
COMPLETED_MARKER = b"completed location="
BUF_SIZE = 32

CONFIGS = ("neither", "main_only", "lib_only", "both")
BINARY_FOR_CONFIG = {
    "neither": "boundary_neither",
    "main_only": "boundary_main_only",
    "lib_only": "boundary_lib_only",
    "both": "boundary_both",
}
LIB_FOR_CONFIG = {
    "neither": "libboundary_off.so",
    "main_only": "libboundary_off.so",
    "lib_only": "libboundary_on.so",
    "both": "libboundary_on.so",
}
LOCATIONS = ("in_main", "in_lib")
MODES = ("safe", "attack", "fixed")
REPEATS = 3
SAFE_N = "16"
ATTACK_N = "80"

EFFECT = "controlled_local_effect"
BLOCK = "blocked_before_operation"
DETECT = "detected_after_operation"
UNATTRIBUTED = "unattributed_fault"

# Pre-registered expectation: a canary detects the overflow iff the overflowing
# component itself was built with -fstack-protector-strong. An uninstrumented
# component faults via raw return-address corruption (unattributed_fault). The
# explicit bounds check (fixed) blocks pre-write in every configuration.
_EXPECT_DETECTED = {
    ("main_only", "in_main"),
    ("lib_only", "in_lib"),
    ("both", "in_main"),
    ("both", "in_lib"),
}


def _repair_outcome(observation):
    if observation.get("mode") == "fixed":
        return BLOCK
    return DETECT


def _expectation(observation):
    mode = observation.get("mode")
    if mode == "safe":
        return None  # baseline control, no attack hypothesis
    if mode == "fixed":
        return BLOCK
    key = (observation.get("config"), observation.get("location"))
    return DETECT if key in _EXPECT_DETECTED else UNATTRIBUTED


LAB_POLICY = LabPolicy(
    effect_flags=["copy_completed"],
    repair_outcome=_repair_outcome,
    # For fixed mode, require the explicit bounds-check rejection (clean exit 2
    # + rejection marker); for attack mode, outcomes.py checks aborted() (SIGABRT)
    # and we additionally cross-check canary_abort in coverage/finding.
    block_signal=lambda o: o.get("bounds_rejected") is True and o.get("returncode") == 2,
    strict_block_signal=True,
    unexpected_fault=True,
    expectation=_expectation,
)


def require(condition, message):
    if not condition:
        raise RuntimeError(str(message))


def emitted_canary(objdump_text, func):
    """Whether `func`'s disassembly calls __stack_chk_fail."""
    marker = "<%s>:" % func
    if marker not in objdump_text:
        return None
    body = objdump_text.split(marker, 1)[1].split("\n\n", 1)[0]
    return "__stack_chk_fail" in body


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
    shutil.copy2(__file__, output / "capture-boundary.py")
    shutil.copy2(ROOT / "scripts/research/outcomes.py", output / "outcomes.py")
    shutil.copy2("/etc/os-release", output / "os-release.txt")
    lab = output / "13-boundary-instrumentation"
    shutil.copytree(ROOT / "labs/13-boundary-instrumentation/src", lab / "src")
    shutil.copy2(ROOT / "labs/13-boundary-instrumentation/Makefile", lab)
    for name, command in (("compiler", [cc, "--version"]), ("compiler-target", [cc, "-dumpmachine"]),
                          ("binutils", ["readelf", "--version"]), ("libc", ["getconf", "GNU_LIBC_VERSION"])):
        record(command, name).check_returncode()
    record(["make", "--always-make", "CC=" + cc, "CFLAGS=" + metadata["CFLAGS"],
            "LDFLAGS=" + metadata["LDFLAGS"]], "build", cwd=lab).check_returncode()

    # --- Emitted link: inspect each binary and shared library separately. ---
    main_emitted = {}
    for cfg in CONFIGS:
        binary = BINARY_FOR_CONFIG[cfg]
        disas = record(["objdump", "-d", str(lab / binary)], binary + ".objdump")
        disas.check_returncode()
        main_emitted[cfg] = emitted_canary(disas.stdout.decode(errors="replace"), "copy_in_main")

    lib_emitted = {}
    for lib_name in ("libboundary_on.so", "libboundary_off.so"):
        disas = record(["objdump", "-d", str(lab / lib_name)], lib_name + ".objdump")
        disas.check_returncode()
        lib_emitted[lib_name] = emitted_canary(disas.stdout.decode(errors="replace"), "copy_in_lib")

    # --- Effective link: run all 4 configs x 2 locations x 3 modes x 3 repeats. ---
    observations = []
    big_src = "A" * 200
    for cfg in CONFIGS:
        binary = str(lab / BINARY_FOR_CONFIG[cfg])
        lib_name = LIB_FOR_CONFIG[cfg]
        for loc in LOCATIONS:
            for mode in MODES:
                n = SAFE_N if mode == "safe" else ATTACK_N
                args = [binary, loc, mode, n, big_src]
                for repeat in range(1, REPEATS + 1):
                    stem = "{}.{}.{}.{}".format(cfg, loc, mode, repeat)
                    res = record(args, stem)
                    rc = res.returncode
                    combined = res.stdout + res.stderr
                    canary_abort = (CANARY_MARKER in combined) and (rc == -signal.SIGABRT)
                    bounds_rejected = (REJECTED_MARKER in res.stderr) and (rc == 2)
                    completed = (COMPLETED_MARKER in res.stdout) and (rc == 0)
                    row = {
                        "config": cfg,
                        "location": loc,
                        "mode": mode,
                        "repeat": repeat,
                        "returncode": rc,
                        "signal": signal.Signals(-rc).name if rc < 0 else None,
                        "copy_completed": completed,
                        "canary_abort": canary_abort,
                        "bounds_rejected": bounds_rejected,
                        "main_emitted_canary": main_emitted[cfg],
                        "lib_emitted_canary": lib_emitted[lib_name],
                    }
                    observations.append(row)
                    (output / "observations.json").write_text(json.dumps(observations, indent=2) + "\n")

    # Determinism: each (config, location, mode) cell SHOULD be single-valued. A
    # cell that varies across repeats is RECORDED, not aborted on (as in Labs 11
    # and 12), so a fluctuating result stays an exportable observation rather than
    # a lost capture. A non-deterministic capture is not an interpretable control
    # baseline, so it only invalidates control_validity below.
    nondeterministic_cells = []
    for cfg in CONFIGS:
        for loc in LOCATIONS:
            for mode in MODES:
                cell = {(r["returncode"], r["copy_completed"], r["canary_abort"], r["bounds_rejected"])
                        for r in observations
                        if r["config"] == cfg and r["location"] == loc and r["mode"] == mode}
                if len(cell) > 1:
                    nondeterministic_cells.append("%s/%s/%s" % (cfg, loc, mode))
    deterministic = not nondeterministic_cells

    # Control validity:
    #   1. Every safe (in-bounds) run completes normally (rc == 0, copy_completed).
    #   2. Every `neither` attack faults without a canary abort (proving the bug).
    #   3. Every `fixed` run is rejected pre-write (rc == 2, bounds_rejected) in all configs.
    safe_ok = all(r["copy_completed"] and r["returncode"] == 0
                  for r in observations if r["mode"] == "safe")
    neither_unguarded = not any(r["canary_abort"]
                                for r in observations
                                if r["config"] == "neither" and r["mode"] == "attack")
    fixed_ok = all(r["bounds_rejected"] and r["returncode"] == 2
                   for r in observations if r["mode"] == "fixed")
    control_valid = bool(safe_ok and neither_unguarded and fixed_ok and deterministic)

    annotated = annotate(observations, LAB_POLICY)
    states = capture_states(observations, LAB_POLICY,
                            control_valid=control_valid, capture_complete=True)

    def attack_rows(cfg, loc):
        return [r for r in observations
                if r["config"] == cfg and r["location"] == loc and r["mode"] == "attack"]

    # Coverage matrix + main-binary-only baseline oracle (e.g. hardening-check
    # run on the main executable without inspecting linked shared libraries).
    coverage_cells = []
    oracle_cells = []
    emitted_not_effective = 0
    fp_count = 0
    fn_count = 0
    for cfg in CONFIGS:
        m_chk = main_emitted[cfg]
        l_chk = lib_emitted[LIB_FOR_CONFIG[cfg]]
        for loc in LOCATIONS:
            rows = attack_rows(cfg, loc)
            target_chk = m_chk if loc == "in_main" else l_chk
            effective = bool(rows) and all(r["canary_abort"] for r in rows)
            disagree = (target_chk is True) and not effective
            emitted_not_effective += int(disagree)
            coverage_cells.append({
                "config": cfg,
                "location": loc,
                "main_emitted_canary": m_chk,
                "lib_emitted_canary": l_chk,
                "target_component_emitted_canary": target_chk,
                "effective": effective,
                "emitted_but_not_effective": disagree,
            })

            verdict = "protected" if m_chk else "not protected"
            truth = "protected" if effective else "not protected"
            is_fp = verdict == "protected" and truth == "not protected"
            is_fn = verdict == "not protected" and truth == "protected"
            fp_count += int(is_fp)
            fn_count += int(is_fn)
            oracle_cells.append({
                "config": cfg,
                "location": loc,
                "main_only_verdict": verdict,
                "runtime_truth": truth,
                "false_positive": is_fp,
                "false_negative": is_fn,
            })

    (output / "coverage.json").write_text(json.dumps({
        "buf_size": BUF_SIZE,
        "cells": coverage_cells,
        "emitted_but_not_effective_count": emitted_not_effective,
    }, indent=2) + "\n")

    (output / "main_only_oracle.json").write_text(json.dumps({
        "rule": "infer protected iff the main executable emits __stack_chk_fail (ignoring linked shared libraries)",
        "cells": oracle_cells,
        "false_positive_count": fp_count,
        "false_negative_count": fn_count,
        "misclassified_count": fp_count + fn_count,
    }, indent=2) + "\n")

    (output / "states.json").write_text(json.dumps(states, indent=2) + "\n")
    (output / "classified.json").write_text(json.dumps(
        [{"config": r["config"], "location": r["location"], "mode": r["mode"],
          "repeat": r["repeat"], "outcome": r["outcome"],
          "hypothesis_supported": r["hypothesis_supported"]} for r in annotated],
        indent=2) + "\n")

    def detected(cfg, loc):
        rows = attack_rows(cfg, loc)
        return bool(rows) and all(r["canary_abort"] for r in rows)

    (output / "finding.json").write_text(json.dumps({
        "both_protects_main_and_lib": detected("both", "in_main") and detected("both", "in_lib"),
        "main_only_leaves_lib_unprotected": detected("main_only", "in_main") and not detected("main_only", "in_lib"),
        "lib_only_leaves_main_unprotected": not detected("lib_only", "in_main") and detected("lib_only", "in_lib"),
        "neither_protects_neither": not detected("neither", "in_main") and not detected("neither", "in_lib"),
        "bounds_check_blocks_all_configs": fixed_ok,
        "main_only_oracle_false_positives": fp_count,
        "main_only_oracle_false_negatives": fn_count,
        "emitted_but_not_effective_count": emitted_not_effective,
        "deterministic": deterministic,
        "nondeterministic_cells": nondeterministic_cells,
        "control_validity": control_valid,
        "hypothesis_supported": states["hypothesis_supported"],
    }, indent=2) + "\n")

    manifest = [hashlib.sha256(path.read_bytes()).hexdigest() + "  " + str(path.relative_to(output))
                for path in sorted(output.rglob("*")) if path.is_file()]
    (output / "SHA256SUMS").write_text("\n".join(manifest) + "\n")
    (output / "COMPLETE").write_text("Lab 13 capture complete; label: " + label + "\n")


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
    print("Lab 13 captured in " + str(args.output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
