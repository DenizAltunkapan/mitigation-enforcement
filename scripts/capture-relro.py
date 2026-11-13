#!/usr/bin/env python3
"""Build and measure the local x86-64 Lab 09; no external target is accepted.

Lab 09 overwrites a GOT entry and makes the matching library call under partial
and full RELRO. Two cases, three repeats each (6 trials):
  partial  got_partial (-z lazy): the GOT is writable, the call reaches the
           oracle, status 42
  full     got_full (-z now): the GOT is read-only, the write faults, SIGSEGV
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
TARGET_MARKER = b"TARGET: GOT call redirected\n"


def require(condition, message):
    if not condition:
        raise RuntimeError(str(message))


def puts_got_slot(objdump_stdout):
    match = re.search(rb"^([0-9a-f]+)\s+\S+\s+puts(?:@|\s|$)", objdump_stdout, re.MULTILINE)
    require(match, "puts GOT relocation not found")
    return int(match[1], 16)


def capture(label, output):
    require(platform.system() == "Linux" and platform.machine() == "x86_64",
            "requires x86-64 Linux")
    require(os.geteuid() != 0, "run the lab as an ordinary user, not root")
    require(not any(char in str(output) for char in "\r\n"), "output path cannot contain newlines")
    cc = os.environ.get("CC", "gcc")
    for tool in (cc, "make", "readelf", "objdump", "getconf"):
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
    shutil.copy2(__file__, output / "capture-relro.py")
    shutil.copy2("/etc/os-release", output / "os-release.txt")
    lab = output / "09-relro-got"
    shutil.copytree(ROOT / "labs/09-relro-got/src", lab / "src")
    shutil.copy2(ROOT / "labs/09-relro-got/Makefile", lab)
    for name, command in (("compiler", [cc, "--version"]), ("compiler-target", [cc, "-dumpmachine"]),
                          ("binutils", ["readelf", "--version"]), ("libc", ["getconf", "GNU_LIBC_VERSION"])):
        record(command, name).check_returncode()
    record(["make", "--always-make", "CC=" + cc, "CFLAGS=" + metadata["CFLAGS"],
            "LDFLAGS=" + metadata["LDFLAGS"]], "build", cwd=lab).check_returncode()

    # Confirm the RELRO shape of each binary: both request GNU_RELRO; only the
    # full build also has BIND_NOW. Both are non-PIE ET_EXEC with no guard.
    for binary, bind_now in (("got_full", True), ("got_partial", False)):
        elf = record(["readelf", "-W", "-h", "-l", "-d", "-s", str(lab / binary)], binary + ".readelf")
        elf.check_returncode()
        text = elf.stdout.decode()
        require("Advanced Micro Devices X86-64" in text and "ELF64" in text, "unsupported ELF target")
        require(re.search(r"Type:\s+EXEC", text), binary + " is not a non-PIE ET_EXEC")
        require("GNU_RELRO" in text, binary + " has no GNU_RELRO segment")
        require("Symbol table" in text, "readelf did not print a symbol table")
        require("__stack_chk_fail" not in text, "unexpected stack guard symbol")
        require(("BIND_NOW" in text) == bind_now,
                binary + (" should be full RELRO" if bind_now else " should be partial RELRO"))

    # The attacked address is puts's GOT slot, read per binary from the non-PIE
    # artifacts. Full and partial RELRO lay the GOT out differently, so each
    # build has its own slot; attacking the wrong one would prove nothing.
    slots = {}
    for binary in ("got_full", "got_partial"):
        # Relative path and cwd=lab so the recorded output carries no capture path.
        reloc = record(["objdump", "-R", binary], binary + ".got-relocs", cwd=lab)
        reloc.check_returncode()
        slots[binary] = puts_got_slot(reloc.stdout)
    (output / "payload.json").write_text(json.dumps({
        "puts_got_slot": {b: hex(a) for b, a in slots.items()},
        "address_source": "local non-PIE build artifacts (objdump -R); not an information disclosure",
        "action": "write &oracle into the binary's own puts GOT slot, then call puts",
    }, indent=2) + "\n")

    cases = (("partial", "got_partial"), ("full", "got_full"))
    observations = []
    for mode, binary_name in cases:
        for repeat in range(1, 4):
            stem = "{}.{}".format(mode, repeat)
            result = record([str(lab / binary_name), hex(slots[binary_name])], stem)
            rc = result.returncode
            row = {"mode": mode, "binary": binary_name, "repeat": repeat, "returncode": rc,
                   "signal": signal.Signals(-rc).name if rc < 0 else None,
                   "target_reached": TARGET_MARKER in result.stdout}
            observations.append(row)
            (output / "observations.json").write_text(json.dumps(observations, indent=2) + "\n")
            if mode == "partial":
                require(rc == 42 and row["target_reached"],
                        "partial RELRO did not allow the GOT redirect: " + json.dumps(row))
            else:  # full
                require(rc == -signal.SIGSEGV and not row["target_reached"],
                        "full RELRO did not make the GOT read-only: " + json.dumps(row))

    for mode in ("partial", "full"):
        outcomes = {(r["returncode"], r["target_reached"]) for r in observations if r["mode"] == mode}
        require(len(outcomes) == 1, "mode " + mode + " was not deterministic: " + str(outcomes))

    (output / "finding.json").write_text(json.dumps({
        "partial_relro_got_is_writable": all(r["returncode"] == 42
                                             for r in observations if r["mode"] == "partial"),
        "full_relro_got_is_read_only": all(r["returncode"] == -signal.SIGSEGV
                                           for r in observations if r["mode"] == "full"),
    }, indent=2) + "\n")

    manifest = [hashlib.sha256(path.read_bytes()).hexdigest() + "  " + str(path.relative_to(output))
                for path in sorted(output.rglob("*")) if path.is_file()]
    (output / "SHA256SUMS").write_text("\n".join(manifest) + "\n")
    (output / "COMPLETE").write_text("Lab 09 checks passed; label: " + label + "\n")


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
    print("Lab 09 captured in " + str(args.output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
