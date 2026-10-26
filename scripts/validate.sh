#!/usr/bin/env bash
# One local/CI entry point; no downloads, privileges or VM startup.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"
for tool in python3 gcc make readelf objdump getconf sha256sum; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        echo "Validation requires ${tool}. See README.md for prerequisites." >&2
        exit 1
    fi
done
for script in scripts/*.sh; do
    bash -n "${script}"
done
python3 -m unittest discover -s tests -v
