#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DISK="${ROOT}/images/modern.qcow2"
SEED="${ROOT}/images/modern-seed.iso"

if [[ ! -f "${DISK}" || ! -f "${SEED}" ]]; then
    "${ROOT}/scripts/setup-modern-vm.sh"
fi

if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
    echo "qemu-system-x86_64 is required. Install qemu-system-x86." >&2
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

exec qemu-system-x86_64 \
    "${ACCEL_OPTS[@]}" \
    -m 2048 \
    -smp 2 \
    -drive file="${DISK}",if=virtio,format=qcow2 \
    -drive file="${SEED}",if=virtio,format=raw \
    -net nic,model=virtio \
    -net user,hostfwd=tcp:127.0.0.1:2223-:22 \
    "${DISPLAY_OPTS[@]}"
