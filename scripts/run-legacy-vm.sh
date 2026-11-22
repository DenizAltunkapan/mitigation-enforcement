#!/usr/bin/env bash
# Boots the installed legacy VM. SSH is forwarded to localhost:2222
# (root / toor, see legacy-preseed.cfg).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DISK="${LEGACY_DISK:-${ROOT}/images/legacy.qcow2}"

if [[ ! -f "${DISK}" ]]; then
    echo "${DISK} not found. Run ./setup-legacy-vm.sh first." >&2
    exit 1
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

SNAPSHOT_OPTS=()
case "${SNAPSHOT:-0}" in
    0) ;;
    1) SNAPSHOT_OPTS=(-snapshot) ;;
    *) echo "SNAPSHOT must be 0 or 1." >&2; exit 2 ;;
esac

NETWORK_OPTS=(-net nic -net user,hostfwd=tcp:127.0.0.1:2222-:22)
case "${OFFLINE:-0}" in
    0) ;;
    1) NETWORK_OPTS=(-net none) ;;
    *) echo "OFFLINE must be 0 or 1." >&2; exit 2 ;;
esac

exec qemu-system-i386 \
    ${ACCEL_OPTS[@]+"${ACCEL_OPTS[@]}"} \
    ${SNAPSHOT_OPTS[@]+"${SNAPSHOT_OPTS[@]}"} \
    -m 512 \
    -drive file="${DISK}",format=qcow2 \
    "${NETWORK_OPTS[@]}" \
    "${DISPLAY_OPTS[@]}"
