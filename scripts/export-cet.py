#!/usr/bin/env python3
"""Export a complete Lab 11 capture as portable text evidence.

Unlike the Labs 04-10 exporters, this one does NOT require the result to match an
expectation. It requires the capture to be COMPLETE (all data recorded) and
internally consistent, then carries the four research states and the activation
chain through verbatim. A counter-finding (hypothesis_supported false) exports
exactly like a supporting one; that is the point of the lab.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys

PROFILES = ("cet_full", "cet_none")
RUNTIMES = ("default", "shstk")
MODES = ("attack", "safe")
REPEATS = 3
SEGV_CPERR = 10


def parse_shstk_status(stderr_text):
    """The per-process shadow-stack status the tested binary printed for itself.
    Kept in sync with scripts/capture-cet.py; the exporter re-derives it from the
    raw stderr so the stored shstk_active field cannot drift from the trace."""
    if "SHSTK_STATUS=unavailable" in stderr_text:
        return None
    match = re.search(r"SHSTK_STATUS=0x([0-9a-f]+)", stderr_text)
    if not match:
        return None
    return (int(match.group(1), 16) & 0x1) == 1


def parse_segv_cperr(stderr_text):
    """Whether the fault was a control-protection fault (SEGV_CPERR); None if no
    fault was reported. Kept in sync with scripts/capture-cet.py."""
    match = re.search(r"SEGV_SI_CODE=(-?\d+)", stderr_text)
    if not match:
        return None
    return int(match.group(1)) == SEGV_CPERR
DESCRIPTION = (
    "Selected text evidence from complete Lab 11 captures (CET shadow-stack "
    "requested-vs-enforced). Binaries and disassembly remain in the capture "
    "directories. The four research states and the activation chain are carried "
    "through unchanged; a counter-finding exports like any complete capture. "
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
    if (root / "COMPLETE").read_text() != "Lab 11 capture complete; label: " + label + "\n":
        raise ValueError("not a completed Lab 11 capture")
    observations = json.loads((root / "observations.json").read_text())
    expected = {(p, rt, m, rep) for p in PROFILES for rt in RUNTIMES
                for m in MODES for rep in range(1, REPEATS + 1)}
    actual = {(r["profile"], r["runtime"], r["mode"], r["repeat"]) for r in observations}
    if len(observations) != len(expected) or actual != expected:
        raise ValueError("expected exactly %d unique observations" % len(expected))
    rows = []
    for row in observations:
        stem = "{profile}.{runtime}.{mode}.{repeat}".format(**row)
        status = json.loads((root / (stem + ".status.json")).read_text())
        if status["returncode"] != row["returncode"]:
            raise ValueError("observation/status mismatch: " + stem)
        stdout = (root / (stem + ".stdout.txt")).read_text()
        # The claim-bearing raw evidence (SHSTK_STATUS=, SEGV_SI_CODE=) is on
        # stderr, so it must travel with the observation. Cross-check that the
        # derived shstk_active / segv_cperr fields actually match that raw text,
        # using the collector's own parsers (single source of truth), so a hand-
        # edited observation cannot claim an activation or a fault the trace does
        # not show.
        stderr = (root / (stem + ".stderr.txt")).read_text()
        if parse_shstk_status(stderr) != row.get("shstk_active"):
            raise ValueError("shstk_active does not match the stderr trace: " + stem)
        if parse_segv_cperr(stderr) != row.get("segv_cperr"):
            raise ValueError("segv_cperr does not match the stderr trace: " + stem)
        rows.append(dict(row, stdout=stdout, stderr=stderr))
    lab = root / "11-cet-shadow-stack"
    return {
        "name": root.name,
        "environment": environment,
        "versions": {name: (root / (name + ".stdout.txt")).read_text() for name in
                     ("compiler", "compiler-target", "binutils", "libc")},
        "os_release": (root / "os-release.txt").read_text(),
        "build_command": json.loads((root / "build.command.json").read_text()),
        "build_stdout": (root / "build.stdout.txt").read_text(),
        "activation_chain": json.loads((root / "activation_chain.json").read_text()),
        "states": json.loads((root / "states.json").read_text()),
        "classified": json.loads((root / "classified.json").read_text()),
        "finding": json.loads((root / "finding.json").read_text()),
        "artifact_sha256": {name: sha256(path) for name, path in {
            "src/shadow_stack.c": lab / "src/shadow_stack.c",
            "Makefile": lab / "Makefile",
            **{name: lab / name for name in PROFILES},
        }.items()},
        "collector_sha256": sha256(root / "capture-cet.py"),
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
