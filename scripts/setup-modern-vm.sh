#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOWNLOADS="${ROOT}/downloads"
IMAGES="${ROOT}/images"
BASE_URL="https://cloud.debian.org/images/cloud/trixie/latest"
IMAGE="debian-13-generic-amd64.qcow2"
BASE_IMAGE="${DOWNLOADS}/${IMAGE}"
DISK="${IMAGES}/modern.qcow2"
SEED="${IMAGES}/modern-seed.iso"

mkdir -p "${DOWNLOADS}" "${IMAGES}"

if ! command -v curl >/dev/null 2>&1; then
    echo "curl is required" >&2
    exit 1
fi

if ! command -v qemu-img >/dev/null 2>&1; then
    echo "qemu-img is required. Install qemu-utils." >&2
    exit 1
fi

if [[ ! -f "${BASE_IMAGE}" ]]; then
    curl -fL --progress-bar -o "${BASE_IMAGE}" "${BASE_URL}/${IMAGE}"
fi

curl -fsSL -o "${DOWNLOADS}/SHA512SUMS" "${BASE_URL}/SHA512SUMS"

(
    cd "${DOWNLOADS}"
    grep " ${IMAGE}\$" SHA512SUMS | sha512sum -c -
)

if [[ ! -f "${DISK}" ]]; then
    qemu-img create -f qcow2 -F qcow2 -b "${BASE_IMAGE}" "${DISK}" 20G
fi

SEED_DIR="${IMAGES}/modern-seed"
USER_DATA="${SEED_DIR}/user-data"
META_DATA="${SEED_DIR}/meta-data"

mkdir -p "${SEED_DIR}"

cat >"${USER_DATA}" <<'EOF'
#cloud-config
hostname: modern
users:
  - name: lab
    groups: sudo
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: false
    passwd: "$6$exploitevolab$41dGzJp7J8E7AbKIp67bROkeoOC2gzj3IBDfYtXMRS05fVUewTM3a/6E0q5riwz7rfd4REP/Eyxr8sD/5fFxU1"
ssh_pwauth: true
package_update: true
packages:
  - build-essential
  - gdb
  - gcc
  - git
  - curl
  - make
EOF

cat >"${META_DATA}" <<'EOF'
instance-id: exploit-evolution-modern
local-hostname: modern
EOF

if command -v cloud-localds >/dev/null 2>&1; then
    cloud-localds "${SEED}" "${USER_DATA}" "${META_DATA}"
elif command -v genisoimage >/dev/null 2>&1; then
    (
        cd "${SEED_DIR}"
        genisoimage -quiet -output "${SEED}" -volid cidata -joliet -rock \
            user-data meta-data
    )
else
    echo "cloud-localds or genisoimage is required for the seed ISO." >&2
    echo "Install cloud-image-utils or genisoimage." >&2
    exit 1
fi

echo "Modern VM is ready:"
echo "  disk: ${DISK}"
echo "  seed: ${SEED}"
