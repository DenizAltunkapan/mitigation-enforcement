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

### Legacy 32-bit LiveCD

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

This is a read-only LiveCD baseline. Store any notes or results in this host
repository, not only inside the VM session.

## Non-Goals

- Not a weaponized exploit collection.
- Not a chapter-by-chapter reproduction of any book.
- No copyrighted source code, disk images or third-party binaries are committed.
- No scanning or attacking real systems.

## License

MIT. See [LICENSE](LICENSE).
