#!/usr/bin/env python3
"""Record the actual, observed capabilities of the current environment.

Phase 0 of the research plan (research/plan.yaml). The per-lab collectors already
record the compiler, linker, C library and kernel string of a capture. This probe
records what they do not: the dynamic loader identity, CPU security features
actually advertised (NX, SMEP/SMAP, user-space shadow stack, IBT), the ASLR
setting, relevant GLIBC tunables, and the versions of the hardening-relevant
packages. Its purpose is RQ1: moving from "a mitigation was requested" to "the
platform actually supports and activates it" requires this evidence, separate
from any single lab.

The output is a JSON document describing one environment. It is written to a file
(or stdout) and is meant to be pasted, per environment, into
research/environments.lock.json so that every recorded result names a pinned,
independently probed environment.

This probe only reads and reports. It builds nothing, runs no lab binary, and
changes no system setting. Run it once per environment (host and each VM):

    python3 scripts/research/probe_environment.py --label host --output env-host.json
    # inside the modern VM:
    python3 scripts/research/probe_environment.py --label modern --output env-modern.json
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path


def run(command):
    """Return stripped stdout of a command, or None if it is unavailable."""
    tool = command[0]
    if shutil.which(tool) is None:
        return None
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def first_line(text):
    return text.splitlines()[0].strip() if text else None


def read_text(path):
    try:
        return Path(path).read_text()
    except OSError:
        return None


def toolchain():
    cc = "gcc"
    return {
        "compiler": first_line(run([cc, "--version"])),
        "compiler_target": run([cc, "-dumpmachine"]),
        "linker": first_line(run(["ld", "--version"])),
        "assembler": first_line(run(["as", "--version"])),
        "libc": run(["getconf", "GNU_LIBC_VERSION"]),
        "ldd": first_line(run(["ldd", "--version"])),
        "gdb": first_line(run(["gdb", "--version"])),
        "make": first_line(run(["make", "--version"])),
        "python": sys.version.split()[0],
    }


def dynamic_loader():
    """Identity and hash of the dynamic loader actually in use."""
    candidates = [
        "/lib64/ld-linux-x86-64.so.2",
        "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
    ]
    for path in candidates:
        p = Path(path)
        if p.exists():
            target = p
            # Resolve a symlink to the real loader so the hash is of the loader
            # itself, not of a link.
            try:
                target = p.resolve()
            except OSError:
                pass
            data = read_bytes(target)
            return {
                "path": path,
                "resolved": str(target),
                "sha256": hashlib.sha256(data).hexdigest() if data is not None else None,
                "size": len(data) if data is not None else None,
            }
    return None


def read_bytes(path):
    try:
        return Path(path).read_bytes()
    except OSError:
        return None


# CPU flags relevant to the mitigations this project measures. Presence in
# /proc/cpuinfo means the running kernel advertises the feature; it is not proof
# that a given process has it enabled (that is a per-lab, per-process check).
RELEVANT_CPU_FLAGS = (
    "nx", "smep", "smap", "user_shstk", "ibt", "pku", "la57",
)


def cpu_features():
    cpuinfo = read_text("/proc/cpuinfo") or ""
    flags = set()
    for line in cpuinfo.splitlines():
        if line.startswith("flags") and ":" in line:
            flags.update(line.split(":", 1)[1].split())
            break
    return {flag: (flag in flags) for flag in RELEVANT_CPU_FLAGS}


def aslr_setting():
    return (read_text("/proc/sys/kernel/randomize_va_space") or "").strip() or None


def os_release():
    text = read_text("/etc/os-release") or ""
    fields = {}
    for line in text.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            fields[key] = value.strip().strip('"')
    return {
        "pretty_name": fields.get("PRETTY_NAME"),
        "id": fields.get("ID"),
        "version_id": fields.get("VERSION_ID"),
    }


# Hardening-relevant packages whose exact version affects what a build emits or
# what the runtime enforces. dpkg only; non-Debian systems report null.
PINNED_PACKAGES = (
    "gcc", "binutils", "libc6", "libc6-dev", "make", "gdb",
)


def package_versions():
    if shutil.which("dpkg-query") is None:
        return None
    versions = {}
    for name in PINNED_PACKAGES:
        out = run(["dpkg-query", "-W", "-f=${Version}", name])
        versions[name] = out or None
    return versions


def glibc_tunables():
    import os
    return os.environ.get("GLIBC_TUNABLES")


def probe(label):
    document = {
        "schema_version": 1,
        "label": label,
        "label_is_operator_supplied": True,
        "probed_at_utc": datetime.now(timezone.utc).isoformat(),
        "uname": run(["uname", "-a"]),
        "kernel_release": platform.release(),
        "architecture": platform.machine(),
        "platform": platform.platform(),
        "os_release": os_release(),
        "toolchain": toolchain(),
        "dynamic_loader": dynamic_loader(),
        "cpu_features": cpu_features(),
        "aslr_randomize_va_space": aslr_setting(),
        "glibc_tunables": glibc_tunables(),
        "packages_dpkg": package_versions(),
    }
    # A short, stable signature over the identity-bearing fields, so two probes of
    # "the same" environment can be compared at a glance. Timestamp is excluded.
    identity = {
        k: document[k] for k in (
            "kernel_release", "architecture", "os_release", "toolchain",
            "dynamic_loader", "cpu_features", "packages_dpkg",
        )
    }
    document["identity_sha256"] = hashlib.sha256(
        json.dumps(identity, sort_keys=True).encode()
    ).hexdigest()
    return document


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--label", required=True,
                        help="operator-supplied environment label, e.g. host or modern")
    parser.add_argument("--output", type=Path,
                        help="write JSON here (default: stdout)")
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,30}", args.label):
        parser.error("label must be a short lowercase token")
    document = json.dumps(probe(args.label), indent=2) + "\n"
    if args.output:
        if args.output.exists():
            parser.error("refusing to overwrite existing file: %s" % args.output)
        args.output.write_text(document)
        print("Environment probe written to %s" % args.output)
    else:
        sys.stdout.write(document)
    return 0


if __name__ == "__main__":
    sys.exit(main())
