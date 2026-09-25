#!/usr/bin/env bash
# Unattended install of Debian 7 (Wheezy) i386 into images/legacy.qcow2.
#
# Preseed drives the installer non-interactively and SSH is enabled from
# first boot, so labs can be run and their output captured without relying
# on a graphical session.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOWNLOADS="${ROOT}/downloads"
IMAGES="${ROOT}/images"
BASE_URL="https://cdimage.debian.org/mirror/cdimage/archive/7.11.0/i386/iso-cd"
ISO_NAME="debian-7.11.0-i386-netinst.iso"
ISO="${DOWNLOADS}/${ISO_NAME}"
DISK="${IMAGES}/legacy.qcow2"
DISK_SIZE="8G"
PRESEED_PORT=8000

mkdir -p "${DOWNLOADS}" "${IMAGES}"

if ! command -v curl >/dev/null 2>&1; then
    echo "curl is required" >&2
    exit 1
fi

if ! command -v qemu-img >/dev/null 2>&1 || ! command -v qemu-system-i386 >/dev/null 2>&1; then
    echo "qemu-img and qemu-system-i386 are required. Install qemu-system-x86 and qemu-utils." >&2
    exit 1
fi

for tool in udisksctl genisoimage; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        echo "${tool} is required to build the auto-installing ISO. Install it." >&2
        exit 1
    fi
done

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

# Build a remastered ISO whose default boot entry already carries the
# preseed URL, so the installer starts unattended with no boot-menu prompt
# to type into.
#
# Two earlier approaches were tried and rejected:
#   - Typing the preseed URL at the boot prompt works, but QEMU's GTK window
#     doesn't support pasting, and the boot prompt's US keyboard layout
#     makes manual typing error-prone on a non-US host keyboard.
#   - Passing the preseed URL via -kernel/-initrd/-append (bypassing the
#     boot menu entirely) produced a disk with the base system installed
#     but no GRUB whatsoever (confirmed via debugfs: no /boot/grub, no
#     grub-install binary) — reproduced on two separate install attempts.
#     That path apparently breaks grub-installer's ability to identify/write
#     to the target disk.
# Remastering the ISO's default boot entry keeps the installer on the same
# boot path grub-installer expects (normal CD boot) while still requiring
# no manual input.
REMASTER_DIR="${IMAGES}/legacy-iso-remaster"
PRESEEDED_ISO="${IMAGES}/legacy-preseeded.iso"

if [[ ! -f "${PRESEEDED_ISO}" ]]; then
    echo "Building auto-installing ISO (one-time, cached at ${PRESEEDED_ISO})..."

    rm -rf "${REMASTER_DIR}"
    mkdir -p "${REMASTER_DIR}"

    LOOP_DEV="$(udisksctl loop-setup -f "${ISO}" --no-user-interaction | sed -n 's/.*as \(\/dev\/loop[0-9]*\)\.$/\1/p')"
    if [[ -z "${LOOP_DEV}" ]]; then
        echo "Failed to set up a loop device for ${ISO}" >&2
        exit 1
    fi
    cleanup_loop() {
        udisksctl unmount -b "${LOOP_DEV}p1" >/dev/null 2>&1 || true
        udisksctl loop-delete -b "${LOOP_DEV}" >/dev/null 2>&1 || true
    }
    trap cleanup_loop EXIT

    # udisks auto-mounts the ISO9660 partition as soon as the loop device
    # appears, so an explicit `udisksctl mount` call races it and usually
    # fails with AlreadyMounted. Poll for the mount instead of mounting
    # ourselves.
    MOUNT_POINT=""
    for _ in $(seq 1 20); do
        MOUNT_POINT="$(findmnt -no TARGET "${LOOP_DEV}p1" 2>/dev/null || true)"
        [[ -n "${MOUNT_POINT}" ]] && break
        sleep 0.5
    done
    if [[ -z "${MOUNT_POINT}" ]]; then
        echo "Failed to find the auto-mounted location of ${LOOP_DEV}p1" >&2
        exit 1
    fi

    cp -a "${MOUNT_POINT}/." "${REMASTER_DIR}/"
    chmod -R u+w "${REMASTER_DIR}"

    cleanup_loop
    trap - EXIT

    # Point the default "install" boot entry at our preseed file, served
    # from the QEMU user-net gateway (10.0.2.2) that's reachable from inside
    # the guest during install.
    sed -i \
        "s|append vga=788 initrd=/install.386/initrd.gz -- quiet|append vga=788 initrd=/install.386/initrd.gz auto=true priority=critical url=http://10.0.2.2:${PRESEED_PORT}/legacy-preseed.cfg -- quiet|" \
        "${REMASTER_DIR}/isolinux/txt.cfg"

    # Boot menu shows briefly, then boots the (now preseeded) default entry
    # on its own — no keypress required. Timeout is in tenths of a second.
    sed -i "s/^timeout .*/timeout 50/" "${REMASTER_DIR}/isolinux/isolinux.cfg"

    genisoimage -o "${PRESEEDED_ISO}" \
        -r -J \
        -b isolinux/isolinux.bin \
        -c isolinux/boot.cat \
        -no-emul-boot -boot-load-size 4 -boot-info-table \
        -V "Debian 7 Preseed" \
        "${REMASTER_DIR}" >/dev/null

    rm -rf "${REMASTER_DIR}"
fi

PRESEED_DIR="${ROOT}/scripts"
python3 -m http.server "${PRESEED_PORT}" --directory "${PRESEED_DIR}" &
HTTP_PID=$!
trap 'kill "${HTTP_PID}" 2>/dev/null || true' EXIT

echo
echo "Booting the auto-installing ISO. The boot menu appears briefly, then"
echo "installation starts on its own: partitioning, base system, package"
echo "install, GRUB, SSH server, all unattended. Let it fully finish and"
echo "reboot on its own before closing this window."
echo

qemu-system-i386 \
    "${ACCEL_OPTS[@]}" \
    -m 512 \
    -drive file="${DISK}",format=qcow2 \
    -cdrom "${PRESEEDED_ISO}" \
    -boot d \
    -net nic -net user \
    -display gtk

echo
echo "Install VM exited. If the installer completed, run ./run-legacy-vm.sh."
