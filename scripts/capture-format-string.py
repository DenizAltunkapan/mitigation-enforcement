#!/usr/bin/env python3
"""Build and measure the local x86-64 Lab 10; no external target is accepted.

Lab 10 exercises a format-string bug as a read and a write primitive, and the
glibc FORTIFY mitigation and a root-cause repair. Four cases, three repeats each (12 trials):
  leak    format_plain with a %p walk -> the stack marker LEAKMARK appears
  write   format_plain with %n        -> status 42 (test variable becomes 4)
  fortify format_fortified with %n    -> SIGABRT (glibc rejects %n before writing)
  fixed   format_fixed with %n        -> literal output (fixed format string)
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
MARKER = b"4c45414b4d41524b"  # STACK_MARKER "LEAKMARK", as %p prints it
LEAK_WALK = ".%p" * 24
# glibc's FORTIFY abort message for a %n in a writable format. The exact wording
# is version-dependent ("segment" in glibc 2.39, "segments" in 2.43), so match the
# stable part rather than one release's phrasing.
FORTIFY_MESSAGE = re.compile(rb"%n in writable segment[s]? detected")
WRITE_MARKER = b"TARGET: format write changed the test variable\n"


def require(condition, message):
    if not condition:
        raise RuntimeError(str(message))


def capture(label, output):
    require(platform.system() == "Linux" and platform.machine() == "x86_64",
            "requires x86-64 Linux")
    require(os.geteuid() != 0, "run the lab as an ordinary user, not root")
    require(not any(char in str(output) for char in "\r\n"), "output path cannot contain newlines")
    cc = os.environ.get("CC", "gcc")
    for tool in (cc, "make", "readelf", "getconf"):
        require(shutil.which(tool), "required tool not found: " + tool)
    output.mkdir()  # Exclusive, including dangling symlinks.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    env = dict(os.environ, LC_ALL="C", SHELL="/bin/sh")

    def record(command, stem, **kwargs):
        (output / (stem + ".command.json")).write_text(json.dumps(command) + "\n")
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
                "python": sys.version, "CC": cc, "CFLAGS": env.get("CFLAGS", "-Wall -Wextra"),
                "LDFLAGS": env.get("LDFLAGS", "")}
    (output / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")
    shutil.copy2(__file__, output / "capture-format-string.py")
    shutil.copy2("/etc/os-release", output / "os-release.txt")
    lab = output / "10-format-string"
    shutil.copytree(ROOT / "labs/10-format-string/src", lab / "src")
    shutil.copy2(ROOT / "labs/10-format-string/Makefile", lab)
    for name, command in (("compiler", [cc, "--version"]), ("compiler-target", [cc, "-dumpmachine"]),
                          ("binutils", ["readelf", "--version"]), ("libc", ["getconf", "GNU_LIBC_VERSION"])):
        record(command, name).check_returncode()
    record(["make", "--always-make", "CC=" + cc, "CFLAGS=" + metadata["CFLAGS"],
            "LDFLAGS=" + metadata["LDFLAGS"]], "build", cwd=lab).check_returncode()

    # All are non-PIE ET_EXEC. The fortified build calls __printf_chk (the glibc
    # FORTIFY entry point); the plain build calls plain printf. That symbol
    # difference is what makes the fortify case meaningful.
    for binary, fortified in (("format_plain", False), ("format_fortified", True),
                              ("format_fixed", False)):
        elf = record(["readelf", "-W", "-h", "-s", str(lab / binary)], binary + ".readelf")
        elf.check_returncode()
        text = elf.stdout.decode()
        require("Advanced Micro Devices X86-64" in text and "ELF64" in text, "unsupported ELF target")
        require(re.search(r"Type:\s+EXEC", text), binary + " is not a non-PIE ET_EXEC")
        require("Symbol table" in text, "readelf did not print a symbol table")
        require(("__printf_chk" in text) == fortified,
                binary + (" is not fortified" if fortified else " is unexpectedly fortified"))

    (output / "payload.json").write_text(json.dumps({
        "leak_format": LEAK_WALK,
        "stack_marker": "0x" + MARKER.decode(),
        "write_format": "AAAA%n",
        "note": "the program supplies a pointer to a local test variable; controlling "
                "an arbitrary destination without that pointer is out of scope",
    }, indent=2) + "\n")

    cases = (
        ("leak", "format_plain", LEAK_WALK),
        ("write", "format_plain", "AAAA%n"),
        ("fortify", "format_fortified", "AAAA%n"),
        ("fixed", "format_fixed", "AAAA%n"),
    )
    observations = []
    for mode, binary_name, fmt in cases:
        for repeat in range(1, 4):
            stem = "{}.{}".format(mode, repeat)
            result = record([str(lab / binary_name), fmt], stem)
            rc = result.returncode
            row = {"mode": mode, "binary": binary_name, "repeat": repeat, "returncode": rc,
                   "signal": signal.Signals(-rc).name if rc < 0 else None,
                   "marker_leaked": MARKER in result.stdout,
                   "target_written": WRITE_MARKER in result.stdout,
                   "safe_input_literal": result.stdout == b"AAAA%n\n",
                   "fortify_detected": FORTIFY_MESSAGE.search(result.stderr) is not None}
            observations.append(row)
            (output / "observations.json").write_text(json.dumps(observations, indent=2) + "\n")
            if mode == "leak":
                require(rc == 0 and row["marker_leaked"],
                        "the %p walk did not disclose the stack marker: " + json.dumps(row))
            elif mode == "write":
                require(rc == 42 and row["target_written"] and not row["fortify_detected"],
                        "the %n write did not change the test variable: " + json.dumps(row))
            elif mode == "fortify":
                require(rc == -signal.SIGABRT and row["fortify_detected"] and not row["target_written"],
                        "FORTIFY did not reject the %n write: " + json.dumps(row))
            else:  # fixed
                require(rc == 0 and row["safe_input_literal"] and not row["target_written"],
                        "fixed format did not print the input literally: " + json.dumps(row))

    for mode in ("leak", "write", "fortify", "fixed"):
        outcomes = {(r["returncode"], r["marker_leaked"], r["target_written"],
                     r["safe_input_literal"], r["fortify_detected"])
                    for r in observations if r["mode"] == mode}
        require(len(outcomes) == 1, "mode " + mode + " was not deterministic: " + str(outcomes))

    (output / "finding.json").write_text(json.dumps({
        "format_string_discloses_stack_memory": all(r["marker_leaked"]
                                                     for r in observations if r["mode"] == "leak"),
        "write_primitive_reaches_local_target": all(r["returncode"] == 42 and r["target_written"]
                                                      for r in observations if r["mode"] == "write"),
        "fortify_rejects_the_n_write": all(r["returncode"] == -signal.SIGABRT and r["fortify_detected"]
                                           for r in observations if r["mode"] == "fortify"),
        "fixed_format_prints_input_literally": all(r["returncode"] == 0 and r["safe_input_literal"]
                                                  for r in observations if r["mode"] == "fixed"),
    }, indent=2) + "\n")

    manifest = [hashlib.sha256(path.read_bytes()).hexdigest() + "  " + str(path.relative_to(output))
                for path in sorted(output.rglob("*")) if path.is_file()]
    (output / "SHA256SUMS").write_text("\n".join(manifest) + "\n")
    (output / "COMPLETE").write_text("Lab 10 checks passed; label: " + label + "\n")


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
    print("Lab 10 captured in " + str(args.output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
