#!/usr/bin/env python3
"""Capture Lab 04 on Linux with Python 3.8+; retain failed runs for diagnosis."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import shutil
import signal
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
BINARIES = ("stack_unprotected", "stack_canary", "stack_fixed")


def run(command, **kwargs):
    return subprocess.run(command, capture_output=True, timeout=30, **kwargs)


def require(condition, detail):
    if not condition:
        raise RuntimeError("Unexpected observation: " + str(detail))


def capture(label, output):
    # mkdir is exclusive, including dangling symlinks and concurrent invocations.
    output.mkdir()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    env = dict(os.environ, LC_ALL="C")
    cc = env.get("CC", "gcc")
    flags = env.get("CFLAGS", "-O0 -g -Wall -Wextra -fno-omit-frame-pointer")
    ldflags = env.get("LDFLAGS", "")
    metadata = {
        "label": label, "label_is_operator_supplied": True,
        "captured_at_utc": datetime.now(timezone.utc).isoformat(),
        "platform": platform.platform(), "architecture": platform.machine(),
        "python": sys.version, "CC": cc, "CFLAGS": flags, "LDFLAGS": ldflags,
        "aslr": Path("/proc/sys/kernel/randomize_va_space").read_text().strip(),
    }
    (output / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")
    shutil.copy2(__file__, output / "capture-stack-canary.py")
    lab = output / "04-stack-canary"
    shutil.copytree(ROOT / "labs" / "04-stack-canary" / "src", lab / "src")
    shutil.copy2(ROOT / "labs" / "04-stack-canary" / "Makefile", lab)
    for name, command in (
        ("compiler", [cc, "--version"]),
        ("compiler-target", [cc, "-dumpmachine"]),
        ("binutils", ["readelf", "--version"]),
        ("libc", ["getconf", "GNU_LIBC_VERSION"]),
    ):
        result = run(command, env=env)
        (output / (name + ".txt")).write_bytes(result.stdout + result.stderr)
        result.check_returncode()
    linker = run([cc, "-print-prog-name=ld"], env=env)
    linker.check_returncode()
    result = run([os.fsdecode(linker.stdout.strip()), "--version"], env=env)
    (output / "linker.txt").write_bytes(result.stdout + result.stderr)
    result.check_returncode()
    if Path("/etc/os-release").exists():
        shutil.copy2("/etc/os-release", output / "os-release.txt")
    command = ["make", "--always-make", "CC=" + cc, "CFLAGS=" + flags,
               "LDFLAGS=" + ldflags]
    (lab / "build-command.json").write_text(json.dumps(command) + "\n")
    result = run(command, cwd=lab, env=env)
    (lab / "build.txt").write_bytes(result.stdout + result.stderr)
    result.check_returncode()
    observations = []
    for binary in BINARIES:
        for suffix, command in (
            ("readelf", ["readelf", "-W", "-h", "-l", "-d", "-s", binary]),
            ("disassembly", ["objdump", "-d", binary]),
        ):
            result = run(command, cwd=lab, env=env)
            (lab / (binary + "." + suffix + ".txt")).write_bytes(result.stdout + result.stderr)
            result.check_returncode()
        symbols = (lab / (binary + ".readelf.txt")).read_text()
        require(("__stack_chk_fail" in symbols) == (binary != "stack_unprotected"), binary)
        for mode, size in (("safe", 16), ("overflow", 128)):
            payload = b"A" * size
            (lab / (mode + ".input")).write_bytes(payload)
            for repeat in range(1, 4):
                stem = "{}.{}.{}".format(binary, mode, repeat)
                try:
                    result = run([str(lab / binary), mode], input=payload, cwd=lab, env=env)
                except subprocess.TimeoutExpired as error:
                    (lab / (stem + ".stdout.txt")).write_bytes(error.stdout or b"")
                    (lab / (stem + ".stderr.txt")).write_bytes(error.stderr or b"")
                    (lab / (stem + ".timeout.json")).write_text(
                        json.dumps({"timeout_seconds": error.timeout, "command": error.cmd}) + "\n")
                    raise
                (lab / (stem + ".stdout.txt")).write_bytes(result.stdout)
                (lab / (stem + ".stderr.txt")).write_bytes(result.stderr)
                returned = b"returned from copy_input\n" in result.stdout
                observation = {
                    "binary": binary, "mode": mode, "repeat": repeat,
                    "returncode": result.returncode,
                    "signal": signal.Signals(-result.returncode).name if result.returncode < 0 else None,
                    "returned_from_copy": returned,
                }
                observations.append(observation)
                # Persist each observation before validation, including failures.
                (lab / "observations.json").write_text(json.dumps(observations, indent=2) + "\n")
                if mode == "safe":
                    require(result.returncode == 0 and returned, observation)
                elif binary == "stack_canary":
                    require(result.returncode == -signal.SIGABRT and not returned, observation)
                    require(b"stack smashing detected" in result.stderr, observation)
                elif binary == "stack_fixed":
                    require(result.returncode == 2 and not returned, observation)
                    require(b"rejected: input exceeds buffer capacity" in result.stderr, observation)
                # Undefined behavior without a guard has no required outcome.
    manifest = []
    for path in sorted(output.rglob("*")):
        if path.is_file():
            manifest.append(hashlib.sha256(path.read_bytes()).hexdigest() + "  " +
                            str(path.relative_to(output)))
    (output / "SHA256SUMS").write_text("\n".join(manifest) + "\n")
    (output / "COMPLETE").write_text("Lab 04 checks passed; label: " + label + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("label", choices=("legacy", "modern", "host"))
    parser.add_argument("output", type=lambda value: Path(value).absolute())
    args = parser.parse_args()
    try:
        capture(args.label, args.output)
    except (OSError, subprocess.SubprocessError, RuntimeError) as error:
        print("Capture failed (partial evidence retained): " + str(error), file=sys.stderr)
        return 1
    print("Lab 04 captured in " + str(args.output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
