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

### Scriptable Legacy 32-bit VM

The preferred legacy baseline is a scriptable Debian 7 ("Wheezy") i386 VM.
Unlike the book LiveCD, this VM is installable, persistent and reachable over
SSH, so lab output can be captured without relying on a graphical session.

- image: `debian-7.11.0-i386-netinst.iso`
- source: <https://cdimage.debian.org/mirror/cdimage/archive/7.11.0/i386/iso-cd/>
- checksum file: <https://cdimage.debian.org/mirror/cdimage/archive/7.11.0/i386/iso-cd/SHA256SUMS>

Install it:

```bash
./scripts/setup-legacy-vm.sh
```

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

### Optional Legacy 32-bit LiveCD

The legacy baseline uses the official LiveCD distributed through O'Reilly's
example-material repository for *Hacking: The Art of Exploitation, 2nd
Edition*:

- image: `hacking-live-1.0.iso`
- source: <https://resources.oreilly.com/examples/9781593271442/-/tree/master/Hacking%20The%20Art%20of%20Exploitation%202nd%20Edition%20Jon%20Erickson%20Official%20LiveCD%20ISO%20No%20Starch%20Press>
- MD5: `bd7a7dfa2e0ce37e3115cdd8f3830783`

Download and verify it:

```bash
./scripts/setup-legacy-livecd.sh
```

Start it:

```bash
./scripts/run-legacy-livecd.sh
```

This is a read-only historical reference. Store any notes or results in this
host repository, not only inside the VM session.

## Labs

The first labs build the vocabulary needed before touching memory-corruption
bugs:

- [Lab 01 - Process Memory Layout](labs/01-process-memory-layout/README.md)
- [Lab 02 - Stack Frames and Calling Conventions](labs/02-stack-frames/README.md)

Run labs inside each VM and copy the observed output back into the matching
lab notes. The interesting part is the comparison between legacy 32-bit Linux
and modern x86-64 Linux, not just the program output itself.

## Non-Goals

- Not a weaponized exploit collection.
- Not a chapter-by-chapter reproduction of any book.
- No copyrighted source code, disk images or third-party binaries are committed.
- No scanning or attacking real systems.

## License

MIT. See [LICENSE](LICENSE).
