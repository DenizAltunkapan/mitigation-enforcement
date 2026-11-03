# Exploit Evolution

[![Lab validation](https://github.com/DenizAltunkapan/exploit-evolution/actions/workflows/labs.yml/badge.svg)](https://github.com/DenizAltunkapan/exploit-evolution/actions/workflows/labs.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](README.md#quickstart)

A systems-security lab for comparing classical exploitation primitives on
legacy 32-bit Linux and modern x86-64 Linux.

The point is not to collect exploits. The point is to document why an old
exploit path worked, which modern mitigation changes the path, what additional
primitive would be needed today and how the underlying bug should actually be
fixed.

## Quickstart

On x86 Linux, install Bash, Python 3.8+, GCC, GDB, GNU Make, Binutils,
coreutils, QEMU utilities (`qemu-img`) and e2fsprogs (`mke2fs`, `e2fsck`,
`debugfs`). From the repository root:

```bash
./scripts/validate.sh
```

This verifies builds, tooling and evidence integrity locally. No VM startup,
ISO download, root access or network access is needed. For a new host capture,
see [local review commands](#review-locally). A host run does not substitute
for the recorded VM measurements.

## Research question and current result

How do architecture, toolchain defaults and runtime mitigations change the
path from a memory-safety bug to an exploitation primitive?

The strongest completed experiment is [Lab 04](labs/04-stack-canary/README.md):
the same local buffer overwrite is compared with stack protection disabled,
enabled, and with an explicit bounds check. In the
[recorded host and Debian VM runs](labs/04-stack-canary/RESULTS.md), the guard
detects corruption after the invalid write; the bounds check prevents the write.
The experiment includes two optimization levels, repeated trials, raw output
and source/build hashes.

Labs 01–03 now include a [Debian 7 i386 / Debian 13 amd64 comparison](docs/BASELINE-COMPARISON.md):
matching source and build inputs, 30 runtime transcripts, verified manifests and
a modern GDB transcript. Non-PIE text remained fixed while the modern default
PIE text moved; heap, stack and libc mappings moved in both environments.

This is an independent educational research project in progress. The historical
installation was recovered, and native legacy Lab 04 replication remains open. See the
[methodology, evidence status and next experiments](docs/RESEARCH.md) for the
limits of the results and the remaining work.

## Review locally

With the [Quickstart prerequisites](#quickstart) installed, run these optional
host captures from the repository root:

```bash
python3 scripts/capture-stack-canary.py host /tmp/canary-review
python3 scripts/export-stack-canary.py /tmp/canary-review \
  --output /tmp/canary-review.json
python3 scripts/capture-return-overwrite.py host /tmp/overwrite-review
python3 scripts/export-return-overwrite.py /tmp/overwrite-review \
  --output /tmp/overwrite-review.json
# Optional Labs 01–03 host capture and verified text export:
bash scripts/capture-baseline.sh host /tmp/baseline-review
python3 scripts/export-baseline.py /tmp/baseline-review \
  --output /tmp/baseline-review.json
```

Use fresh output paths. Validation builds disposable examples, exercises failure
handling and checks evidence integrity without root, networking or VM startup.
The C examples intentionally include undefined behavior; use a disposable VM
for manual experiments. A host test confirms the local tooling and does not
substitute for VM measurements.

## VM Baselines

### Modern x86-64 VM

The modern baseline uses the official Debian 13 ("Trixie") generic cloud image:

- image: `debian-13-generic-amd64.qcow2`
- source: <https://cloud.debian.org/images/cloud/trixie/latest/>
- checksum file: <https://cloud.debian.org/images/cloud/trixie/latest/SHA512SUMS>

Set up the VM:

```bash
./scripts/setup-modern-vm.sh
```

Start it:

```bash
./scripts/run-modern-vm.sh
```

SSH is forwarded to `localhost:2223`.

```bash
ssh lab@localhost -p 2223
```

The lab password is `lab`. SSH binds only to host loopback. QEMU user-mode
networking allows outbound connections; it is not an air gap. These public
credentials are only for disposable local lab VMs. Do not bridge the guest
onto a LAN or expose its SSH port to other hosts.

### Legacy 32-bit VM

The selected legacy distribution is Debian 7 ("Wheezy") i386. The setup script
is intended to produce a persistent installation with SSH. The recorded baseline
uses a recovered installation with serial login; a fresh unattended install and
its SSH transport still need independent validation.

- image: `debian-7.11.0-i386-netinst.iso`
- source: <https://cdimage.debian.org/mirror/cdimage/archive/7.11.0/i386/iso-cd/>
- checksum file: <https://cdimage.debian.org/mirror/cdimage/archive/7.11.0/i386/iso-cd/SHA256SUMS>

Install it:

```bash
./scripts/setup-legacy-vm.sh
```

This builds an ISO with preseed in the default boot entry and starts the
installer. Let it finish and reboot before closing the window, then verify
normal disk boot and login. The earlier local installation required a separate
bootloader recovery; the script's end-to-end success is not yet established.

Start it:

```bash
./scripts/run-legacy-vm.sh
```

SSH is forwarded to `localhost:2222`.

```bash
ssh root@localhost -p 2222
```

The lab password is `toor`. SSH binds only to host loopback. The installer
temporarily serves the preseed configuration on `127.0.0.1:8000`; stop any other
service on that port before installation. QEMU user-mode networking allows
outbound connections; it is not an air gap. Keep this obsolete guest disposable
and do not bridge it onto a LAN or expose its SSH port to other hosts.

### Disposable VM sessions

Once a VM is installed, run it with temporary disk writes for experiments:

```bash
SNAPSHOT=1 HEADLESS=1 ./scripts/run-modern-vm.sh
# Use a known bootable disk; the original local legacy disk lacks GRUB.
LEGACY_DISK="$PWD/images/legacy-recovered-20261026.qcow2" \
  SNAPSHOT=1 OFFLINE=1 HEADLESS=1 ./scripts/run-legacy-vm.sh
```

`SNAPSHOT=1` passes QEMU's `-snapshot` option. Guest disk writes are discarded
when QEMU exits; copy evidence out before shutdown. Without it, writes persist.
Snapshot mode does not repair a broken installation or replace network isolation.
`OFFLINE=1` removes the guest network device and SSH forwarding. It applies to
the running guest, not to setup downloads. Both options accept only `0` or `1`.
The modern launcher's automatic setup can still create missing VM files; install
the baseline before using this mode.

The original local legacy disk does not boot normally: an
[offline inspection](docs/LEGACY-DIAGNOSIS.md) found no GRUB installation despite
a successful read-only filesystem check. The guide includes a reproducible inspection
command, the verified recovery procedure and the acceptance criteria for a
fresh installation. The recovered image is a local ignored artifact, unavailable
in a fresh clone; it provides serial login but has no SSH or GDB installed.

## Labs

Labs 01–03 establish the baseline; Labs 04–05 introduce controlled
memory-corruption experiments:

| Lab | Topic | Target | Recorded evidence |
|---|---|---|---|
| [01](labs/01-process-memory-layout/README.md) | Process memory layout | i386 / x86-64 | Verified Debian VM comparison |
| [02](labs/02-stack-frames/README.md) | Stack frames | i386 / x86-64 | VM comparison and modern GDB transcript |
| [03](labs/03-binary-mitigation-baseline/README.md) | ELF mitigations | i386 / x86-64 | Verified VM metadata and runs |
| [04](labs/04-stack-canary/README.md) | Stack canary | x86-64 host / VM | [72 trials](labs/04-stack-canary/RESULTS.md), `-O0` / `-O2` |
| [05](labs/05-return-address-overwrite/README.md) | Return-address overwrite | x86-64 host / VM | [4 variants, 54 trials](labs/05-return-address-overwrite/RESULTS.md) |

Labs 01–03 share a cross-lab [baseline report](docs/BASELINE-RESULTS.md) and
[comparison evidence](docs/evidence/). The independent Lab 04 and 05 captures
have `RESULTS.md` and `evidence/` within their own lab directories.

## Capture Baselines

Run inside each VM, using a new output directory whose parent exists:

```bash
./scripts/capture-baseline.sh legacy /tmp/exploit-evolution-legacy
# In the modern VM:
./scripts/capture-baseline.sh modern /tmp/exploit-evolution-modern
```

Captures environment versions, build commands, source copies, checksums,
three runs per binary, ELF metadata and disassembly. `COMPLETE` marks a
successful capture; failed captures remain available for diagnosis. Existing
output directories are never overwritten.

Requires Bash, a compiler, Make, Binutils and coreutils; GDB is optional.
Override builds with `CC` (compiler executable), `CFLAGS` and `LDFLAGS`.
Use the `host` label for local smoke tests; it does not replace VM results.

The [current comparison](docs/BASELINE-COMPARISON.md) uses preserved Debian VM
captures with matching source, Makefiles, collector and build variables. Export
one or more complete capture directories on the review machine:

```bash
python3 scripts/export-baseline.py /path/to/legacy-baseline /path/to/modern-baseline \
  --output /tmp/baseline-comparison.json
```

The exporter verifies every manifest and exact artifact coverage before writing.
For multiple captures it rejects mismatched inputs. It does not identify VMs,
authenticate measurements or isolate architecture from compiler/libc/kernel
differences. ELF indicators alone do not prove protection of a particular code
path. VM downloads and packages are not pinned, so recorded versions do not
guarantee identical future installations.

Lab 04 uses a dedicated collector with repeated safe/oversized inputs, signal
recording and checks of guard detection versus bounds-check rejection:

```bash
python3 scripts/capture-stack-canary.py host /tmp/exploit-evolution-canary
```

Requires Linux and Python 3.8+; see the Lab 04 instructions for legacy-toolchain
limitations and interpretation. Its results complement the Labs 01–03 baseline.

### Local validation

```bash
./scripts/validate.sh
```

Tests build and run the examples on the host without booting VMs or requiring
root.

## Non-Goals

- Not a weaponized exploit collection.
- Not a chapter-by-chapter reproduction of any book.
- No copyrighted source code, disk images or third-party binaries are committed.
- No scanning or attacking real systems.

## License

MIT. See [LICENSE](LICENSE).
