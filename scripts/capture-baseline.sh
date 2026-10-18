#!/usr/bin/env bash
# Run inside the environment being measured. Keep raw evidence and exact builds.
set -euo pipefail
export LC_ALL=C

usage() {
    echo "Usage: $0 <legacy|modern|host> <new-output-directory>" >&2
}
if [[ $# -ne 2 ]]; then
    usage
    exit 2
fi
LABEL="$1"
case "${LABEL}" in
    legacy|modern|host) ;;
    *) usage; exit 2 ;;
esac
OUTPUT="$2"
if [[ -z "${OUTPUT}" || -e "${OUTPUT}" || -L "${OUTPUT}" ]]; then
    echo "Output must be a new directory; existing results are never overwritten." >&2
    exit 2
fi
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CC="${CC:-gcc}"
CFLAGS="${CFLAGS:--O0 -g -Wall -Wextra -fno-omit-frame-pointer}"
LDFLAGS="${LDFLAGS:-}"
for tool in "${CC}" make readelf objdump sha256sum uname date getconf cp mkdir cat; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        echo "Required tool not found: ${tool}" >&2
        exit 1
    fi
done
# mkdir, without -p, also prevents accidental replacement in concurrent runs.
mkdir -- "${OUTPUT}"
OUTPUT="$(cd "${OUTPUT}" && pwd)"
# Absence of COMPLETE marks a partial or failed capture; retain it for diagnosis.
{
    echo "environment_label=${LABEL} (operator-supplied; not auto-detected)"
    echo "captured_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "architecture=$(uname -m)"
    echo "kernel=$(uname -srvo)"
    echo "word_bits=$(getconf LONG_BIT)"
    echo "CC=${CC}"
    echo "CFLAGS=${CFLAGS}"
    echo "LDFLAGS=${LDFLAGS}"
    echo "runs_per_binary=3"
    echo
    echo '--- operating system ---'
    if [[ -r /etc/os-release ]]; then cat /etc/os-release; fi
    if [[ -r /etc/debian_version ]]; then cat /etc/debian_version; fi
    echo '--- compiler ---'
    "${CC}" --version
    echo '--- compiler target ---'
    "${CC}" -dumpmachine
    echo '--- linker ---'
    "${CC}" -print-prog-name=ld | while IFS= read -r linker; do "${linker}" --version; done
    echo '--- binutils ---'
    readelf --version
    echo '--- libc ---'
    getconf GNU_LIBC_VERSION
    echo '--- ASLR ---'
    cat /proc/sys/kernel/randomize_va_space
    echo '--- GDB (optional) ---'
    if command -v gdb >/dev/null 2>&1; then gdb --version; else echo 'not installed'; fi
} > "${OUTPUT}/environment.txt" 2>&1
cp -- "${BASH_SOURCE[0]}" "${OUTPUT}/capture-baseline.sh"

for lab in 01-process-memory-layout 02-stack-frames 03-binary-mitigation-baseline; do
    LAB_OUTPUT="${OUTPUT}/${lab}"
    mkdir -- "${LAB_OUTPUT}"
    cp -R -- "${ROOT}/labs/${lab}/src" "${LAB_OUTPUT}/src"
    cp -- "${ROOT}/labs/${lab}/Makefile" "${LAB_OUTPUT}/Makefile"
    (
        cd "${LAB_OUTPUT}"
        make --always-make CC="${CC}" CFLAGS="${CFLAGS}" LDFLAGS="${LDFLAGS}" > build.txt 2>&1
        case "${lab}" in
            01-*) BINARIES=(memory_layout) ;;
            02-*) BINARIES=(stack_frames) ;;
            03-*) BINARIES=(mitigation_default mitigation_hardened mitigation_no_pie) ;;
        esac
        for binary in "${BINARIES[@]}"; do
            for run in 1 2 3; do
                "./${binary}" > "${binary}.run-${run}.txt" 2>&1
            done
            readelf -W -h -l -d -s "${binary}" > "${binary}.readelf.txt"
            objdump -d "${binary}" > "${binary}.disassembly.txt"
        done
        sha256sum Makefile src/*.c "${BINARIES[@]}" *.txt > SHA256SUMS
    )
done
(
    cd "${OUTPUT}"
    sha256sum environment.txt capture-baseline.sh */SHA256SUMS > SHA256SUMS
)
printf 'Capture completed. Label: %s\n' "${LABEL}" > "${OUTPUT}/COMPLETE"
printf 'Baseline captured in %s\n' "${OUTPUT}"
