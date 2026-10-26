#!/usr/bin/env python3
"""Export verified Lab 04 captures as portable text evidence (Python 3.8+)."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys

BINARIES = ("stack_unprotected", "stack_canary", "stack_fixed")
DESCRIPTION = (
    "Selected text evidence from verified complete Lab 04 captures. "
    "Full binaries and disassembly remain in the original capture directories. "
    "Checksums establish consistency, not authenticity."
)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_capture(root):
    """Check exact manifest coverage without following artifact symlinks."""
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
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or path.as_posix() != name:
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
    if label not in ("host", "modern", "legacy"):
        raise ValueError("invalid environment label")
    if (root / "COMPLETE").read_text() != "Lab 04 checks passed; label: " + label + "\n":
        raise ValueError("not a completed Lab 04 capture")
    lab = root / "04-stack-canary"
    observations = json.loads((lab / "observations.json").read_text())
    expected = {(binary, mode, repeat) for binary in BINARIES
                for mode in ("safe", "overflow") for repeat in range(1, 4)}
    actual = {(row["binary"], row["mode"], row["repeat"]) for row in observations}
    if len(observations) != 18 or actual != expected:
        raise ValueError("expected exactly 18 unique observations")
    rows = []
    for row in observations:
        stem = "{binary}.{mode}.{repeat}".format(**row)
        rows.append(dict(row, stdout=(lab / (stem + ".stdout.txt")).read_text(),
                         stderr=(lab / (stem + ".stderr.txt")).read_text()))
    return {
        "name": root.name,
        "environment": environment,
        "versions": {name: (root / (name + ".txt")).read_text() for name in
                     ("compiler", "compiler-target", "linker", "binutils", "libc", "os-release")},
        "build_command": json.loads((lab / "build-command.json").read_text()),
        "build_log": (lab / "build.txt").read_text(),
        "artifact_sha256": {name: sha256(lab / name) for name in
                            ("src/stack_copy.c", "Makefile", "safe.input", "overflow.input", *BINARIES)},
        "collector_sha256": sha256(root / "capture-stack-canary.py"),
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
        # Validate every capture before creating output; exclusive creation also
        # preserves existing files and dangling symlinks.
        with args.output.open("x") as output:
            output.write(data)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("Export failed: " + str(error), file=sys.stderr)
        return 1
    print("Verified text evidence exported to " + str(args.output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
