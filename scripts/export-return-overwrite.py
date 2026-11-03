#!/usr/bin/env python3
"""Export a verified complete Lab 05 capture as portable text evidence."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys

BINARIES = ("overwrite_plain", "overwrite_canary", "overwrite_pie", "overwrite_fixed")
DESCRIPTION = (
    "Selected text evidence from verified complete Lab 05 captures. "
    "Full binaries and disassembly remain in the original capture directories. "
    "Checksums establish consistency, not authenticity."
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
    if (root / "COMPLETE").read_text() != "Lab 05 checks passed; label: " + label + "\n":
        raise ValueError("not a completed Lab 05 capture")
    observations = json.loads((root / "observations.json").read_text())
    expected = {(binary, mode, repeat) for binary in BINARIES
                for mode in (("safe", "attack", "padding") if binary == "overwrite_plain"
                             else ("safe", "attack")) for repeat in range(1, 4)}
    actual = {(row["binary"], row["mode"], row["repeat"]) for row in observations}
    if len(observations) != 27 or actual != expected:
        raise ValueError("expected exactly 27 unique observations")
    rows = []
    for row in observations:
        stem = "{binary}.{mode}.{repeat}".format(**row)
        status = json.loads((root / (stem + ".status.json")).read_text())
        if status["returncode"] != row["returncode"]:
            raise ValueError("observation/status mismatch: " + stem)
        rows.append(dict(row, stdout=(root / (stem + ".stdout.txt")).read_text(),
                         stderr=(root / (stem + ".stderr.txt")).read_text()))
    lab = root / "05-return-address-overwrite"
    return {
        "name": root.name,
        "environment": environment,
        "versions": {name: (root / (name + ".stdout.txt")).read_text() for name in
                     ("compiler", "compiler-target", "binutils", "gdb-version", "libc")},
        "os_release": (root / "os-release.txt").read_text(),
        "build_command": json.loads((root / "build.command.json").read_text()),
        "build_stdout": (root / "build.stdout.txt").read_text(),
        "build_stderr": (root / "build.stderr.txt").read_text(),
        "payload": json.loads((root / "payload.json").read_text()),
        "target_trace": (root / "target-trace.stdout.txt").read_text(),
        "artifact_sha256": {name: sha256(path) for name, path in {
            "src/return_overwrite.c": lab / "src/return_overwrite.c",
            "Makefile": lab / "Makefile",
            **{name: root / name for name in ("safe.input", "attack.input", "padding.input")},
            **{name: lab / name for name in BINARIES},
        }.items()},
        "collector_sha256": sha256(root / "capture-return-overwrite.py"),
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
