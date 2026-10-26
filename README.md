# Exploit Evolution

A systems-security lab for comparing classical exploitation primitives on
legacy 32-bit Linux and modern x86-64 Linux.

The point is not to collect exploits. The point is to document why an old
exploit path worked, which modern mitigation changes the path, what additional
primitive would be needed today and how the underlying bug should actually be
fixed.

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

This is an independent educational research project in progress. Labs 01–03
contain preliminary observations from mixed environments. A complete historical
32-bit versus modern comparison remains open: the current legacy disk did not
reach SSH during the latest recorded attempt. See the
[methodology, evidence status and next experiments](docs/RESEARCH.md) for the
limits of the results and the remaining work.

## Review locally

On x86 Linux, install Bash, Python 3.8+, GCC, GNU Make, Binutils and coreutils.
From the repository root:

```bash
./scripts/validate.sh
python3 scripts/capture-stack-canary.py host /tmp/canary-review
python3 scripts/export-stack-canary.py /tmp/canary-review \
  --output /tmp/canary-review.json
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

The legacy baseline is a scriptable Debian 7 ("Wheezy") i386 VM. It is
installable, persistent and reachable over SSH, so lab output can be
captured without relying on a graphical session.

- image: `debian-7.11.0-i386-netinst.iso`
- source: <https://cdimage.debian.org/mirror/cdimage/archive/7.11.0/i386/iso-cd/>
- checksum file: <https://cdimage.debian.org/mirror/cdimage/archive/7.11.0/i386/iso-cd/SHA256SUMS>

Install it:

```bash
./scripts/setup-legacy-vm.sh
```

This builds a self-installing ISO (preseed baked into the default boot
entry) and runs the install fully unattended — no keyboard input required.
Let the installer finish and reboot on its own before closing the window.

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

## Labs

Labs 01–03 establish the baseline; Lab 04 introduces a controlled
memory-corruption experiment:

- [Lab 01 - Process Memory Layout](labs/01-process-memory-layout/README.md)
- [Lab 02 - Stack Frames and Calling Conventions](labs/02-stack-frames/README.md)
- [Lab 03 - Binary Mitigation Baseline](labs/03-binary-mitigation-baseline/README.md)
- [Lab 04 - Stack Canary: Detection Versus Repair](labs/04-stack-canary/README.md)

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

The current lab tables mix historical LiveCD, Debian VM and Ubuntu host
measurements. Treat them as preliminary until recaptured on consistent
baselines. To isolate mitigation effects, vary one protection at a time
within the same environment. ELF indicators alone do not prove protection
of a particular code path. VM downloads and packages are not pinned, so
recorded versions do not guarantee identical future installations.

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
