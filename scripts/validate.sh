#!/usr/bin/env bash
# One local/CI entry point; no downloads, privileges or VM startup.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

# Required for the host labs (01-07) and the evidence integrity checks.
for tool in python3 gcc make readelf objdump nm gdb getconf sha256sum; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        echo "Validation requires ${tool}. See README.md for prerequisites." >&2
        exit 1
    fi
done
# Optional: only the offline legacy-disk inspection test uses these. When they
# are missing that one test skips itself, so host-only validation still runs.
for tool in qemu-img mke2fs e2fsck debugfs; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        echo "Note: ${tool} not found; the legacy-disk inspection test will be skipped." >&2
    fi
done

for script in scripts/*.sh; do
    bash -n "${script}"
done
python3 -m unittest discover -s tests -v
