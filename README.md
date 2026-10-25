# exploit-evolution

A systems-security lab for comparing classical exploitation primitives on
legacy 32-bit Linux and modern x86-64 Linux.

The point is not to collect exploits. The point is to document why an old
exploit path worked, which modern mitigation changes the path, what additional
primitive would be needed today and how the underlying bug should actually be
fixed.

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

The lab password is `lab`. This VM uses QEMU user-mode networking and should
not be bridged onto a real LAN.

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

The lab password is `toor`. This VM uses QEMU user-mode networking and should
not be bridged onto a real LAN.

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
for script in scripts/*.sh; do bash -n "$script" || exit; done
python3 -m unittest discover -s tests -v
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
