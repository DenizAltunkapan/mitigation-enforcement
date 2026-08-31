#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ISO="${ROOT}/downloads/hacking-live-1.0.iso"

if [[ ! -f "${ISO}" ]]; then
    "${ROOT}/scripts/setup-legacy-livecd.sh"
fi

if ! command -v qemu-system-i386 >/dev/null 2>&1; then
    echo "qemu-system-i386 is required. Install qemu-system-x86." >&2
    exit 1
fi

ACCEL_OPTS=()
if [[ -e /dev/kvm && -r /dev/kvm && -w /dev/kvm ]]; then
    ACCEL_OPTS=(-enable-kvm)
fi

DISPLAY_OPTS=(-display gtk)
if [[ "${HEADLESS:-0}" == "1" ]]; then
    DISPLAY_OPTS=(-nographic)
fi

exec qemu-system-i386 \
    "${ACCEL_OPTS[@]}" \
    -m 512 \
    -cdrom "${ISO}" \
    -boot d \
    -net nic \
    -net user \
    "${DISPLAY_OPTS[@]}"
