#!/usr/bin/env python3
"""Export a complete Lab 13 capture as portable text evidence.

Requires COMPLETE (all data recorded) and exact manifest/hash coverage, not
that any particular config protected any particular call. Cross-checks the
derived canary_abort / bounds_rejected / copy_completed flags against raw
stdout/stderr traces and carries coverage, main_only_oracle and the four
research states through unchanged so counter-findings survive export.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import signal
import sys

CONFIGS = ("neither", "main_only", "lib_only", "both")
LOCATIONS = ("in_main", "in_lib")
MODES = ("safe", "attack", "fixed")
REPEATS = 3
CANARY_MARKER = "stack smashing detected"
REJECTED_MARKER = "rejected: input exceeds buffer capacity"
COMPLETED_MARKER = "completed location="
DESCRIPTION = (
    "Selected text evidence from complete Lab 13 captures (partial "
    "instrumentation across a shared-library boundary). Binaries and "
    "disassembly remain in the capture directories. Coverage, baseline oracle "
    "and four research states are carried through unchanged; a counter-finding "
    "exports like any complete capture. Checksums establish consistency, not "
    "authenticity."
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
    if (root / "COMPLETE").read_text() != "Lab 13 capture complete; label: " + label + "\n":
        raise ValueError("not a completed Lab 13 capture")
    observations = json.loads((root / "observations.json").read_text())
    expected = {(c, loc, m, rep) for c in CONFIGS for loc in LOCATIONS
                for m in MODES for rep in range(1, REPEATS + 1)}
    actual = {(r["config"], r["location"], r["mode"], r["repeat"]) for r in observations}
    if len(observations) != len(expected) or actual != expected:
        raise ValueError("expected exactly %d unique observations" % len(expected))
    rows = []
    for row in observations:
        stem = "{config}.{location}.{mode}.{repeat}".format(**row)
        status = json.loads((root / (stem + ".status.json")).read_text())
        if status["returncode"] != row["returncode"]:
            raise ValueError("observation/status mismatch: " + stem)
        stdout = (root / (stem + ".stdout.txt")).read_text()
        stderr = (root / (stem + ".stderr.txt")).read_text()
        rc = row["returncode"]
        if ((CANARY_MARKER in (stdout + stderr)) and rc == -signal.SIGABRT) != bool(row.get("canary_abort")):
            raise ValueError("canary_abort does not match the output trace: " + stem)
        if ((REJECTED_MARKER in stderr) and rc == 2) != bool(row.get("bounds_rejected")):
            raise ValueError("bounds_rejected does not match stderr: " + stem)
        if ((COMPLETED_MARKER in stdout) and rc == 0) != bool(row.get("copy_completed")):
            raise ValueError("copy_completed does not match stdout: " + stem)
        rows.append(dict(row, stdout=stdout, stderr=stderr))
    lab = root / "13-boundary-instrumentation"
    return {
        "name": root.name,
        "environment": environment,
        "versions": {name: (root / (name + ".stdout.txt")).read_text() for name in
                     ("compiler", "compiler-target", "binutils", "libc")},
        "os_release": (root / "os-release.txt").read_text(),
        "build_command": json.loads((root / "build.command.json").read_text()),
        "build_stdout": (root / "build.stdout.txt").read_text(),
        "coverage": json.loads((root / "coverage.json").read_text()),
        "main_only_oracle": json.loads((root / "main_only_oracle.json").read_text()),
        "states": json.loads((root / "states.json").read_text()),
        "classified": json.loads((root / "classified.json").read_text()),
        "finding": json.loads((root / "finding.json").read_text()),
        "artifact_sha256": {name: sha256(path) for name, path in {
            "src/boundary_main.c": lab / "src/boundary_main.c",
            "src/boundary_lib.c": lab / "src/boundary_lib.c",
            "src/boundary_lib.h": lab / "src/boundary_lib.h",
            "Makefile": lab / "Makefile",
            "libboundary_on.so": lab / "libboundary_on.so",
            "libboundary_off.so": lab / "libboundary_off.so",
            "boundary_both": lab / "boundary_both",
            "boundary_main_only": lab / "boundary_main_only",
            "boundary_lib_only": lab / "boundary_lib_only",
            "boundary_neither": lab / "boundary_neither",
        }.items()},
        "collector_sha256": sha256(root / "capture-boundary.py"),
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
