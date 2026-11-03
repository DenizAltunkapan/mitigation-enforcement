#!/usr/bin/env python3
"""Inspect a stopped, standalone qcow2 legacy disk without mounting or booting it."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys

BLOCK = 4 * 1024 * 1024


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(BLOCK), b""):
            result.update(block)
    return result.hexdigest()


def partitions(mbr, disk_size):
    """Decode only primary DOS partitions; no GPT or extended-partition traversal."""
    if len(mbr) != 512 or mbr[510:] != b"\x55\xaa":
        raise ValueError("missing DOS MBR signature")
    result = []
    for index in range(4):
        entry = mbr[446 + index * 16:462 + index * 16]
        kind = entry[4]
        start, size = struct.unpack_from("<II", entry, 8)
        if kind == 0:
            continue
        if kind == 0xee:
            raise ValueError("GPT disks are outside this inspector's scope")
        if entry[0] not in (0, 0x80) or start == 0 or size == 0 or (start + size) * 512 > disk_size:
            raise ValueError("invalid or out-of-range primary partition")
        result.append({"number": index + 1, "type": kind, "bootable": entry[0] == 0x80,
                       "start_sector": start, "sectors": size})
    return result


def extract_partition(raw, output, start, size):
    """Copy in large blocks, retaining holes and detecting truncated input."""
    zero = bytes(BLOCK)
    result = hashlib.sha256()
    with raw.open("rb") as source, output.open("xb") as target:
        source.seek(start)
        remaining = size
        while remaining:
            block = source.read(min(BLOCK, remaining))
            if not block:
                raise ValueError("truncated partition")
            result.update(block)
            if block == zero[:len(block)]:
                target.seek(len(block), 1)
            else:
                target.write(block)
            remaining -= len(block)
        target.truncate(size)
    return result.hexdigest()


def inspect(disk, output, partition_number):
    for tool in ("qemu-img", "debugfs", "e2fsck"):
        if not shutil.which(tool):
            raise ValueError("required tool not found: " + tool)
    if not disk.is_file():
        raise ValueError("disk must be an existing regular file")
    output.mkdir()  # Exclusive: preserve existing directories and symlinks.
    report = {"captured_at_utc": datetime.now(timezone.utc).isoformat(),
              "disk_name": disk.name, "source_sha256_before": digest(disk),
              "partition_number": partition_number, "commands": []}

    def save():
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")

    def run(command, allowed=(0,)):
        result = subprocess.run(command, capture_output=True, text=True, timeout=600,
                                env=dict(os.environ, LC_ALL="C"))
        report["commands"].append({"command": list(map(str, command)),
                                   "returncode": result.returncode,
                                   "stdout": result.stdout, "stderr": result.stderr})
        save()
        if result.returncode not in allowed:
            raise RuntimeError("command failed: " + str(command[0]))
        return result

    save()
    shutil.copyfile(__file__, output / "inspect-legacy-disk.py")
    for command in (["qemu-img", "--version"], ["debugfs", "-V"], ["e2fsck", "-V"]):
        run(command)
    info = json.loads(run(["qemu-img", "info", "--output=json", "-f", "qcow2", str(disk)]).stdout)
    specific = info.get("format-specific", {}).get("data", {})
    if (info.get("backing-filename") or info.get("data-file") or
            specific.get("data-file") or info.get("encrypted")):
        raise ValueError("only standalone unencrypted qcow2 disks are supported")
    report["image_info"] = info
    raw = output / "disk.raw"
    run(["qemu-img", "convert", "-f", "qcow2", "-O", "raw", str(disk), str(raw)])
    run(["qemu-img", "compare", "-f", "qcow2", "-F", "raw", str(disk), str(raw)])
    with raw.open("rb") as source:
        mbr = source.read(512)
    report["mbr_hex"] = mbr.hex()
    report["primary_partitions"] = partitions(mbr, raw.stat().st_size)
    selected = next((item for item in report["primary_partitions"]
                     if item["number"] == partition_number), None)
    if not selected or selected["type"] != 0x83:
        raise ValueError("selected partition must be a primary Linux (0x83) partition")
    root = output / "root.ext"
    expected = extract_partition(raw, root, selected["start_sector"] * 512, selected["sectors"] * 512)
    report["partition_sha256"] = digest(root)
    if report["partition_sha256"] != expected:
        raise RuntimeError("partition extraction differs from raw image")
    with root.open("rb") as source:
        source.seek(1024 + 56)
        if source.read(2) != b"\x53\xef":
            raise ValueError("selected partition does not have an ext filesystem signature")
    # Read-only checks only. Uncorrected filesystem errors (4) are diagnostic
    # findings, while operational/checker failures abort the inspection.
    result = run(["e2fsck", "-f", "-n", str(root)], allowed=(0, 4))
    report["filesystem_check_returncode"] = result.returncode
    for request in ("ls -l /", "ls -l /boot", "ls -l /boot/grub",
                    "stat /usr/sbin/grub-install", "ls -l /var/log/installer"):
        # debugfs can report lookup errors with exit status zero; retain stderr.
        run(["debugfs", "-R", request, str(root)])
    report["source_sha256_after"] = digest(disk)
    if report["source_sha256_before"] != report["source_sha256_after"]:
        raise RuntimeError("source disk changed during inspection; discard these results")
    save()
    manifest = [digest(path) + "  " + path.name
                for path in sorted(output.iterdir()) if path.is_file()]
    (output / "SHA256SUMS").write_text("\n".join(manifest) + "\n")
    (output / "COMPLETE").write_text("Inspection completed; this is not a VM boot or health check.\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("disk", type=lambda value: Path(value).absolute())
    parser.add_argument("output", type=lambda value: Path(value).absolute(), help="new directory")
    parser.add_argument("--partition", type=int, choices=range(1, 5), default=1)
    args = parser.parse_args()
    try:
        inspect(args.disk, args.output, args.partition)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print("Inspection failed (partial evidence retained): " + str(error), file=sys.stderr)
        return 1
    print("Inspection saved to " + str(args.output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
