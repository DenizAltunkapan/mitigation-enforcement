# VM setup and baseline capture

This guide covers the virtual machines and the baseline capture workflow. For
local verification without a VM, see [Run the checks](../README.md#run-the-checks)
in the root README. For methodology and evidence status, see
[RESEARCH.md](RESEARCH.md).

## VM baselines

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
[offline inspection](LEGACY-DIAGNOSIS.md) found no GRUB installation despite
a successful read-only filesystem check. The guide includes a reproducible inspection
command, the verified recovery procedure and the acceptance criteria for a
fresh installation. The recovered image is a local ignored artifact, unavailable
in a fresh clone; it provides serial login but has no SSH or GDB installed.

## Capture baselines

Run inside each VM, using a new output directory whose parent exists:

```bash
./scripts/capture-baseline.sh legacy /tmp/mitigation-enforcement-legacy
# In the modern VM:
./scripts/capture-baseline.sh modern /tmp/mitigation-enforcement-modern
```

Captures environment versions, build commands, source copies, checksums,
three runs per binary, ELF metadata and disassembly. `COMPLETE` marks a
successful capture; failed captures remain available for diagnosis. Existing
output directories are never overwritten.

Requires Bash, a compiler, Make, Binutils and coreutils; GDB is optional.
Override builds with `CC` (compiler executable), `CFLAGS` and `LDFLAGS`.
Use the `host` label for local smoke tests; it does not replace VM results.

The [current comparison](BASELINE-COMPARISON.md) uses preserved Debian VM
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
python3 scripts/capture-stack-canary.py host /tmp/mitigation-enforcement-canary
```

Requires Linux and Python 3.8+; see the Lab 04 instructions for legacy-toolchain
limitations and interpretation. Its results complement the Labs 01–03 baseline.
