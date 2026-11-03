#!/usr/bin/env python3
"""Export verified Labs 01–03 captures; require matching inputs for comparisons."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys

LABS = {
    "01-process-memory-layout": ("memory_layout",),
    "02-stack-frames": ("stack_frames",),
    "03-binary-mitigation-baseline": ("mitigation_default", "mitigation_hardened", "mitigation_no_pie"),
}
SOURCES = {"01-process-memory-layout": "memory_layout.c",
           "02-stack-frames": "stack_frames.c",
           "03-binary-mitigation-baseline": "mitigation_probe.c"}


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(4 * 1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def manifest(path, expected):
    entries = {}
    for line in path.read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match:
            raise ValueError("invalid manifest entry in " + str(path))
        value, name = match.groups()
        relative = PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts or relative.as_posix() != name:
            raise ValueError("unsafe manifest path: " + name)
        if name in entries:
            raise ValueError("duplicate manifest path: " + name)
        entries[name] = value
    if set(entries) != expected:
        raise ValueError("unexpected manifest coverage in " + str(path))
    for name, value in entries.items():
        if digest(path.parent / name) != value:
            raise ValueError("checksum mismatch: " + str(path.parent / name))
    return entries


def export_capture(root):
    if root.is_symlink() or not root.is_dir():
        raise ValueError("capture must be a directory, not a symlink")
    files = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError("symlink in capture: " + str(path))
        if path.is_file():
            files.add(path.relative_to(root).as_posix())
        elif not path.is_dir():
            raise ValueError("unsupported capture artifact: " + str(path))
    if not {"COMPLETE", "SHA256SUMS"} <= files:
        raise ValueError("incomplete capture: " + str(root))
    expected = {"environment.txt", "capture-baseline.sh"} | {lab + "/SHA256SUMS" for lab in LABS}
    hashes = manifest(root / "SHA256SUMS", expected)
    covered = set(expected) | {"COMPLETE", "SHA256SUMS"}
    for lab, binaries in LABS.items():
        names = {"Makefile", "src/" + SOURCES[lab], "build.txt"} | set(binaries)
        for binary in binaries:
            names |= {binary + ".readelf.txt", binary + ".disassembly.txt"}
            names |= {binary + ".run-{}.txt".format(repeat) for repeat in range(1, 4)}
        entries = manifest(root / lab / "SHA256SUMS", names)
        hashes.update({lab + "/" + name: value for name, value in entries.items()})
        covered |= {lab + "/" + name for name in names}
    if files != covered:
        raise ValueError("capture contains extra or missing artifacts: " + str(root))
    environment = (root / "environment.txt").read_text()
    label_match = re.search(r"^environment_label=(legacy|modern|host) \(operator-supplied; not auto-detected\)$",
                            environment, re.MULTILINE)
    if not label_match:
        raise ValueError("missing operator-supplied environment label")
    label = label_match.group(1)
    if (root / "COMPLETE").read_text() != "Capture completed. Label: " + label + "\n":
        raise ValueError("completion marker does not match environment")
    build_variables = {}
    for key in ("CC", "CFLAGS", "LDFLAGS"):
        matches = re.findall(r"^" + key + r"=(.*)$", environment, re.MULTILINE)
        if len(matches) != 1:
            raise ValueError("missing or ambiguous build variable: " + key)
        build_variables[key] = matches[0]
    selected = {name: (root / name).read_text() for name in sorted(files)
                if (name.endswith((".txt", ".c", ".sh")) or PurePosixPath(name).name in
                    ("Makefile", "SHA256SUMS", "COMPLETE")) and not name.endswith(".disassembly.txt")}
    return {"name": root.name, "label": label, "label_is_operator_supplied": True,
            "build_variables": build_variables, "files": selected,
            "artifact_sha256": hashes, "full_manifest_sha256": digest(root / "SHA256SUMS")}


def comparison_signature(capture):
    names = ["capture-baseline.sh"]
    for lab in LABS:
        names.extend((lab + "/Makefile", lab + "/src/" + SOURCES[lab]))
    return {"artifact_sha256": {name: capture["artifact_sha256"][name] for name in names},
            "build_variables": capture["build_variables"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("captures", nargs="+", type=Path)
    parser.add_argument("--output", required=True, type=Path, help="new JSON file; never overwritten")
    args = parser.parse_args()
    try:
        captures = [export_capture(path) for path in args.captures]
        if len({item["name"] for item in captures}) != len(captures):
            raise ValueError("capture names must be unique")
        signature = comparison_signature(captures[0])
        if any(comparison_signature(item) != signature for item in captures[1:]):
            raise ValueError("comparison inputs differ: collector, C sources, Makefiles or build variables")
        result = {
            "schema_version": 1,
            "description": (
                "Verified Labs 01–03 text evidence. All capture manifests and artifact coverage were checked. "
                "Binaries and disassembly remain in the original full captures. Labels are operator-supplied; "
                "matching inputs do not isolate architecture, compiler, libc or kernel effects. "
                "Hashes establish consistency, not authenticity."),
            "matching_inputs": signature,
            "captures": captures,
        }
        data = json.dumps(result, indent=2) + "\n"
        with args.output.open("x") as output:
            output.write(data)
    except (OSError, ValueError) as error:
        print("Export failed: " + str(error), file=sys.stderr)
        return 1
    print("Verified baseline evidence exported to " + str(args.output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
