#!/usr/bin/env python3
"""Build and measure the local x86-64 Lab 07; no external target is accepted.

Lab 07 tests whether a page's execute permission, not its region, decides if
bytes in it run, and whether W^X is enforced. One binary is probed in three
modes, three times each (9 trials):
  rw   non-executable mapping  -> expect SIGSEGV (NX in effect)
  rx   executable mapping      -> expect the oracle marker (status 0)
  rwx  writable+executable     -> policy-dependent: marker, or mprotect rejected
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
MODES = ("rw", "rx", "rwx")
MARKER = b"CALLED 42\n"
REJECTED = b"REJECTED mprotect"


def require(condition, message):
    if not condition:
        raise RuntimeError(str(message))


def capture(label, output):
    require(platform.system() == "Linux" and platform.machine() == "x86_64",
            "requires x86-64 Linux")
    require(os.geteuid() != 0, "run the lab as an ordinary user, not root")
    require(not any(char in str(output) for char in "\r\n"), "output path cannot contain newlines")
    cc = os.environ.get("CC", "gcc")
    for tool in (cc, "make", "readelf", "objdump", "nm", "getconf"):
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

    nx = "nx" in Path("/proc/cpuinfo").read_text()
    metadata = {"schema_version": 1, "label": label, "label_is_operator_supplied": True,
                "captured_at_utc": datetime.now(timezone.utc).isoformat(),
                "platform": platform.platform(), "architecture": platform.machine(),
                "python": sys.version, "CC": cc, "CFLAGS": env.get("CFLAGS", "-Wall -Wextra"),
                "LDFLAGS": env.get("LDFLAGS", ""), "cpu_advertises_nx": nx}
    (output / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")
    shutil.copy2(__file__, output / "capture-wx.py")
    shutil.copy2("/etc/os-release", output / "os-release.txt")
    lab = output / "07-execution-permission"
    shutil.copytree(ROOT / "labs/07-execution-permission/src", lab / "src")
    shutil.copy2(ROOT / "labs/07-execution-permission/Makefile", lab)
    for name, command in (("compiler", [cc, "--version"]), ("compiler-target", [cc, "-dumpmachine"]),
                          ("binutils", ["readelf", "--version"]), ("libc", ["getconf", "GNU_LIBC_VERSION"])):
        record(command, name).check_returncode()
    record(["make", "--always-make", "CC=" + cc, "CFLAGS=" + metadata["CFLAGS"],
            "LDFLAGS=" + metadata["LDFLAGS"]], "build", cwd=lab).check_returncode()

    binary = lab / "wx_probe"
    elf = record(["readelf", "-W", "-h", "-l", str(binary)], "wx_probe.readelf")
    elf.check_returncode()
    text = elf.stdout.decode()
    require("Advanced Micro Devices X86-64" in text and "ELF64" in text, "unsupported ELF target")
    stack = next(line for line in text.splitlines() if "GNU_STACK" in line)
    require("RW " in stack and "RWE" not in stack, "binary does not request a non-executable stack")

    # Confirm the copied span is exactly the oracle. The program copies
    # `oracle_end - oracle` bytes, so that length must equal the disassembled
    # oracle: same start symbol, instructions covering exactly that byte range,
    # ending in `ret`. objdump runs with a relative path so the recorded header
    # carries no absolute capture path.
    symbols = record(["nm", "--defined-only", "wx_probe"], "symbols", cwd=lab)
    symbols.check_returncode()
    addresses = {}
    for line in symbols.stdout.decode().splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] in ("oracle", "oracle_end"):
            addresses[parts[2]] = int(parts[0], 16)
    require({"oracle", "oracle_end"} <= set(addresses), "oracle symbols not found")
    copied_len = addresses["oracle_end"] - addresses["oracle"]
    require(copied_len > 0, "oracle_end is not after oracle")

    disasm = record(["objdump", "-d", "--disassemble=oracle", "wx_probe"], "oracle-disasm", cwd=lab)
    disasm.check_returncode()
    body = disasm.stdout.decode()
    require("<oracle>:" in body, "oracle symbol not found in disassembly")
    # Each instruction line is "<offset>:\t<hex bytes>\t<mnemonic>"; keep the
    # offset, the opcode bytes and the mnemonic so the span can be checked exactly.
    insns = [(int(m[1], 16), m[2].split(), m[3])
             for m in re.finditer(r"^\s*([0-9a-f]+):\s+([0-9a-f ]+?)\s*\t(\w+)", body, re.MULTILINE)]
    require(insns, "no instructions disassembled for the oracle")
    require(insns[-1][2] == "ret", "oracle does not end in ret")
    require(any("$0x2a" in line for line in body.splitlines()),
            "oracle does not load the expected marker (42)")
    # The disassembled instructions must start at `oracle`, and the final `ret`
    # together with its opcode byte(s) must reach exactly `oracle_end`, so the
    # program's copied length (oracle_end - oracle) is precisely the oracle.
    require(insns[0][0] == addresses["oracle"], "disassembly does not start at the oracle symbol")
    ret_offset, ret_bytes, _ = insns[-1]
    require(ret_offset + len(ret_bytes) == addresses["oracle_end"],
            "the copied length does not end exactly on the oracle's ret: "
            + "ret@%#x +%d != oracle_end@%#x"
            % (ret_offset, len(ret_bytes), addresses["oracle_end"]))

    expectations = {
        # mode: (required returncode or None, stdout predicate)
        "rx": ("marker", lambda out, rc: out.endswith(MARKER) and rc == 0),
        "rw": ("fault", lambda out, rc: rc == -signal.SIGSEGV and MARKER not in out),
        # rwx is policy-dependent; both outcomes are valid and recorded as-is.
        "rwx": ("policy", lambda out, rc: (out.endswith(MARKER) and rc == 0)
                or (REJECTED in out and rc == 3)),
    }
    observations = []
    for mode in MODES:
        kind, predicate = expectations[mode]
        for repeat in range(1, 4):
            stem = "{}.{}".format(mode, repeat)
            result = record([str(binary), mode], stem)
            rc = result.returncode
            row = {"mode": mode, "repeat": repeat, "returncode": rc,
                   "signal": signal.Signals(-rc).name if rc < 0 else None,
                   "marker_printed": MARKER in result.stdout,
                   "mprotect_rejected": REJECTED in result.stdout,
                   "expectation": kind}
            observations.append(row)
            (output / "observations.json").write_text(json.dumps(observations, indent=2) + "\n")
            require(predicate(result.stdout, rc), "unexpected outcome for " + mode + ": " + json.dumps(row))

    # Each mode must be internally consistent across its three repeats.
    by_mode = {mode: {(r["returncode"], r["marker_printed"]) for r in observations if r["mode"] == mode}
               for mode in MODES}
    for mode, results in by_mode.items():
        require(len(results) == 1, "mode " + mode + " was not deterministic: " + str(results))
    # The core finding: rw faults while rx runs the identical bytes.
    require(not any(r["marker_printed"] for r in observations if r["mode"] == "rw"),
            "non-executable mapping unexpectedly executed")
    require(all(r["marker_printed"] for r in observations if r["mode"] == "rx"),
            "executable mapping did not execute the oracle")

    (output / "finding.json").write_text(json.dumps({
        "non_exec_page_faulted": all(r["returncode"] == -signal.SIGSEGV
                                     for r in observations if r["mode"] == "rw"),
        "exec_page_ran_identical_bytes": all(r["marker_printed"]
                                             for r in observations if r["mode"] == "rx"),
        "write_exec_mapping_allowed": any(r["marker_printed"]
                                          for r in observations if r["mode"] == "rwx"),
        "write_exec_mapping_rejected": any(r["mprotect_rejected"]
                                           for r in observations if r["mode"] == "rwx"),
    }, indent=2) + "\n")

    manifest = [hashlib.sha256(path.read_bytes()).hexdigest() + "  " + str(path.relative_to(output))
                for path in sorted(output.rglob("*")) if path.is_file()]
    (output / "SHA256SUMS").write_text("\n".join(manifest) + "\n")
    (output / "COMPLETE").write_text("Lab 07 checks passed; label: " + label + "\n")


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
    print("Lab 07 captured in " + str(args.output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
