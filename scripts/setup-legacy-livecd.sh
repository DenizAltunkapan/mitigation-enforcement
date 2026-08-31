#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOWNLOADS="${ROOT}/downloads"
ISO="${DOWNLOADS}/hacking-live-1.0.iso"
URL="https://resources.oreilly.com/examples/9781593271442/-/raw/master/Hacking%20The%20Art%20of%20Exploitation%202nd%20Edition%20Jon%20Erickson%20Official%20LiveCD%20ISO%20No%20Starch%20Press/hacking-live-1.0.iso"
MD5="bd7a7dfa2e0ce37e3115cdd8f3830783"

mkdir -p "${DOWNLOADS}"

if ! command -v curl >/dev/null 2>&1; then
    echo "curl is required" >&2
    exit 1
fi

if [[ ! -f "${ISO}" ]]; then
    curl -fL --progress-bar -o "${ISO}" "${URL}"
fi

echo "${MD5}  ${ISO}" | md5sum -c -

echo "Legacy LiveCD is ready:"
echo "  iso: ${ISO}"
