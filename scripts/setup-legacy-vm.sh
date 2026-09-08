#!/usr/bin/env bash
# Unattended install of Debian 7 (Wheezy) i386 into images/legacy.qcow2.
#
# Unlike the book LiveCD, this VM is fully scriptable: preseed drives the
# installer non-interactively and SSH is enabled from first boot, so labs
# can be run and their output captured without a graphical session.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOWNLOADS="${ROOT}/downloads"
IMAGES="${ROOT}/images"
BASE_URL="https://cdimage.debian.org/mirror/cdimage/archive/7.11.0/i386/iso-cd"
ISO_NAME="debian-7.11.0-i386-netinst.iso"
ISO="${DOWNLOADS}/${ISO_NAME}"
DISK="${IMAGES}/legacy.qcow2"
DISK_SIZE="8G"

mkdir -p "${DOWNLOADS}" "${IMAGES}"

if ! command -v curl >/dev/null 2>&1; then
    echo "curl is required" >&2
    exit 1
fi

if ! command -v qemu-img >/dev/null 2>&1 || ! command -v qemu-system-i386 >/dev/null 2>&1; then
    echo "qemu-img and qemu-system-i386 are required. Install qemu-system-x86 and qemu-utils." >&2
    exit 1
fi

if [[ ! -f "${ISO}" ]]; then
    curl -fL --progress-bar -o "${ISO}" "${BASE_URL}/${ISO_NAME}"
fi

curl -fsSL -o "${DOWNLOADS}/SHA256SUMS" "${BASE_URL}/SHA256SUMS"
(
    cd "${DOWNLOADS}"
    grep " ${ISO_NAME}\$" SHA256SUMS | sha256sum -c -
)

if [[ -f "${DISK}" ]]; then
    echo "${DISK} already exists. Remove it manually first if you want to reinstall." >&2
    exit 1
fi

qemu-img create -f qcow2 "${DISK}" "${DISK_SIZE}"

ACCEL_OPTS=()
if [[ -e /dev/kvm && -r /dev/kvm && -w /dev/kvm ]]; then
    ACCEL_OPTS=(-enable-kvm)
fi

# Extract the installer kernel/initrd from the ISO and boot them directly
# with -kernel/-initrd/-append. This passes the preseed URL on the kernel
# command line automatically, so there's no boot-menu prompt to type into
# (QEMU's GTK window doesn't support pasting).
BOOT_DIR="${IMAGES}/legacy-boot"
mkdir -p "${BOOT_DIR}"

if ! command -v isoinfo >/dev/null 2>&1; then
    echo "isoinfo is required to extract the installer kernel. Install genisoimage." >&2
    exit 1
fi

isoinfo -i "${ISO}" -x '/install.386/vmlinuz.;1' > "${BOOT_DIR}/vmlinuz" 2>/dev/null
isoinfo -i "${ISO}" -x '/install.386/initrd.gz;1' > "${BOOT_DIR}/initrd.gz" 2>/dev/null

if [[ ! -s "${BOOT_DIR}/vmlinuz" || ! -s "${BOOT_DIR}/initrd.gz" ]]; then
    echo "Failed to extract installer kernel/initrd from ${ISO}" >&2
    exit 1
fi

PRESEED_DIR="${ROOT}/scripts"
PRESEED_PORT="$(python3 - <<'EOF'
import socket

with socket.socket() as sock:
    sock.bind(("", 0))
    print(sock.getsockname()[1])
EOF
)"

python3 -m http.server "${PRESEED_PORT}" --directory "${PRESEED_DIR}" &
HTTP_PID=$!
trap 'kill "${HTTP_PID}" 2>/dev/null || true' EXIT

echo
echo "Booting the installer directly with the preseed URL baked into the"
echo "kernel command line - no boot-menu typing required. This runs fully"
echo "unattended: partitioning, base system, package install, SSH server."
echo "Temporary preseed server: http://10.0.2.2:${PRESEED_PORT}/legacy-preseed.cfg"
echo

qemu-system-i386 \
    "${ACCEL_OPTS[@]}" \
    -m 512 \
    -drive file="${DISK}",format=qcow2 \
    -cdrom "${ISO}" \
    -boot d \
    -net nic -net user \
    -kernel "${BOOT_DIR}/vmlinuz" \
    -initrd "${BOOT_DIR}/initrd.gz" \
    -append "auto=true priority=critical url=http://10.0.2.2:${PRESEED_PORT}/legacy-preseed.cfg" \
    -display gtk

echo
echo "Install VM exited. If the installer completed, run ./run-legacy-vm.sh."
