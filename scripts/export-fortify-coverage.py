#!/usr/bin/env python3
"""Export a complete Lab 12 capture as portable text evidence.

Like the Lab 11 exporter, this requires the capture to be COMPLETE (all data
recorded) and internally consistent, not that any particular cell was checked. It
carries the coverage matrix, the four research states and per-observation stdout
and stderr through unchanged, and cross-checks that the derived fortify_abort /
overflow_completed fields match the raw output, so a hand-edited observation cannot
claim a FORTIFY abort the trace does not show.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys

LEVELS = ("off", "l2", "l3")
VARIANTS = ("static", "runtime", "crosstu")
MODES = ("attack", "safe")
REPEATS = 3
OVERFLOW_MARKER = "buffer overflow detected"
COMPLETED_MARKER = "completed mode="
DESCRIPTION = (
    "Selected text evidence from complete Lab 12 captures (FORTIFY coverage: when "
    "is a buffer copy actually checked?). Binaries and disassembly remain in the "
    "capture directories. The coverage matrix and four research states are carried "
    "through unchanged; a coverage counter-finding exports like any complete "
    "capture. Checksums establish consistency, not authenticity."
)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_capture(root):
    if root.is_symlink() or not root.is_dir():
        raise ValueError("capture must be a directory, not a symlink: " + str(root))
    files = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError("symlink in capture: " + str(path))
        if path.is_file():
            files.add(path.relative_to(root).as_posix())
        elif not path.is_dir():
            raise ValueError("unsupported capture artifact: " + str(path))
    if not {"COMPLETE", "SHA256SUMS"} <= files:
        raise ValueError("capture is incomplete: " + str(root))
    entries = {}
    for line in (root / "SHA256SUMS").read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match:
            raise ValueError("invalid manifest entry: " + line)
        digest, name = match.groups()
        name_path = PurePosixPath(name)
        if name_path.is_absolute() or ".." in name_path.parts or name_path.as_posix() != name:
            raise ValueError("unsafe manifest path: " + name)
        if name in entries:
            raise ValueError("duplicate manifest entry: " + name)
        entries[name] = digest
    if set(entries) != files - {"COMPLETE", "SHA256SUMS"}:
        raise ValueError("manifest does not cover exactly the capture artifacts")
    for name, expected in entries.items():
        if sha256(root / name) != expected:
            raise ValueError("checksum mismatch: " + name)


def export_capture(root):
    verify_capture(root)
    environment = json.loads((root / "environment.json").read_text())
    label = environment["label"]
    if label not in ("host", "modern"):
        raise ValueError("invalid environment label")
    if (root / "COMPLETE").read_text() != "Lab 12 capture complete; label: " + label + "\n":
        raise ValueError("not a completed Lab 12 capture")
    observations = json.loads((root / "observations.json").read_text())
    expected = {(lvl, v, m, rep) for lvl in LEVELS for v in VARIANTS
                for m in MODES for rep in range(1, REPEATS + 1)}
    actual = {(r["level"], r["variant"], r["mode"], r["repeat"]) for r in observations}
    if len(observations) != len(expected) or actual != expected:
        raise ValueError("expected exactly %d unique observations" % len(expected))
    rows = []
    for row in observations:
        stem = "{level}.{variant}.{mode}.{repeat}".format(**row)
        status = json.loads((root / (stem + ".status.json")).read_text())
        if status["returncode"] != row["returncode"]:
            raise ValueError("observation/status mismatch: " + stem)
        stdout = (root / (stem + ".stdout.txt")).read_text()
        stderr = (root / (stem + ".stderr.txt")).read_text()
        # Cross-check the derived fields against the raw output, so the stored
        # fortify_abort / overflow_completed cannot drift from the trace.
        if (OVERFLOW_MARKER in (stdout + stderr)) != bool(row.get("fortify_abort")):
            raise ValueError("fortify_abort does not match the output trace: " + stem)
        if (COMPLETED_MARKER in stdout) != bool(row.get("overflow_completed")):
            raise ValueError("overflow_completed does not match stdout: " + stem)
        rows.append(dict(row, stdout=stdout, stderr=stderr))
    lab = root / "12-fortify-coverage"
    return {
        "name": root.name,
        "environment": environment,
        "versions": {name: (root / (name + ".stdout.txt")).read_text() for name in
                     ("compiler", "compiler-target", "binutils", "libc")},
        "os_release": (root / "os-release.txt").read_text(),
        "build_command": json.loads((root / "build.command.json").read_text()),
        "build_stdout": (root / "build.stdout.txt").read_text(),
        "coverage": json.loads((root / "coverage.json").read_text()),
        "states": json.loads((root / "states.json").read_text()),
        "classified": json.loads((root / "classified.json").read_text()),
        "finding": json.loads((root / "finding.json").read_text()),
        "artifact_sha256": {name: sha256(path) for name, path in {
            "src/fortify_copy.c": lab / "src/fortify_copy.c",
            "src/sink.c": lab / "src/sink.c",
            "src/sink.h": lab / "src/sink.h",
            "Makefile": lab / "Makefile",
            "fortify_off": lab / "fortify_off",
            "fortify_l2": lab / "fortify_l2",
            "fortify_l3": lab / "fortify_l3",
        }.items()},
        "collector_sha256": sha256(root / "capture-fortify-coverage.py"),
        "outcomes_sha256": sha256(root / "outcomes.py"),
        "full_manifest_sha256": sha256(root / "SHA256SUMS"),
        "observations": rows,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("captures", nargs="+", type=Path)
    parser.add_argument("--output", required=True, type=Path, help="new JSON file; never overwritten")
    args = parser.parse_args()
    try:
        captures = [export_capture(path) for path in args.captures]
        if len({item["name"] for item in captures}) != len(captures):
            raise ValueError("capture names must be unique")
        data = json.dumps({"description": DESCRIPTION, "captures": captures}, indent=2) + "\n"
        with args.output.open("x") as output:
            output.write(data)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("Export failed: " + str(error), file=sys.stderr)
        return 1
    print("Verified text evidence exported to " + str(args.output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
