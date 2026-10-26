# Lab 03 - Binary Mitigation Baseline

This lab records which compiler and linker hardening properties are visible in
small Linux executables. It does not exploit a bug. It creates comparable
binary variants and asks what a classical memory-corruption path would need to
learn or bypass before it could become reliable.

## Concepts

Common mitigation signals:

```text
PIE             position-independent executable; program text can move with ASLR
NX              non-executable stack request in the GNU_STACK program header
Stack canary    compiler-inserted guard checked before returning from a function
RELRO           relocation table hardening; full RELRO also resolves symbols early
FORTIFY         libc wrapper checks added when optimization can prove object sizes
```

These properties are not the whole security story. They are useful because they
are easy to measure and they change the assumptions behind older exploit
writeups.

## Build

```bash
make
```

The lab builds three variants:

```text
mitigation_default   distribution compiler and linker defaults
mitigation_hardened  explicit stack protector, RELRO/NOW and no-exec-stack flags
mitigation_no_pie    traditional fixed-address executable for contrast
```

The `mitigation_no_pie` target uses `-no-pie` when the local compiler supports
it. On older toolchains where PIE is not the default, `-fno-pie` is enough to
produce the fixed-address contrast binary.

## Run

```bash
./mitigation_default
./mitigation_hardened
./mitigation_no_pie
```

Run each binary multiple times and compare whether `main` moves:

```bash
for b in mitigation_default mitigation_hardened mitigation_no_pie; do
    echo "== $b =="
    for i in 1 2 3; do "./$b" | sed -n '3p'; done
    echo
done
```

## Inspect

Check the ELF file type:

```bash
file ./mitigation_default ./mitigation_hardened ./mitigation_no_pie
readelf -h ./mitigation_default | grep Type
```

Useful `readelf` types:

```text
EXEC  fixed-address executable
DYN   position-independent executable or shared object
```

Check whether the stack is requested as executable:

```bash
readelf -W -l ./mitigation_hardened | grep GNU_STACK
```

Look for stack-canary support:

```bash
readelf -Ws ./mitigation_hardened | grep __stack_chk_fail
```

Look for RELRO:

```bash
readelf -W -l ./mitigation_hardened | grep GNU_RELRO
readelf -d ./mitigation_hardened | grep BIND_NOW
```

Look for fortified libc wrappers:

```bash
readelf -Ws ./mitigation_hardened | grep _chk
```

`FORTIFY_SOURCE` often needs optimization to transform calls into `_chk`
wrappers. If no fortified symbols appear at `-O0`, rebuild with:

```bash
make clean
make CFLAGS="-O2 -g -Wall -Wextra -fno-omit-frame-pointer"
```

## What To Compare

The [26 October 2026 legacy capture](../../docs/BASELINE-RESULTS.md) preserves
Debian 7 source/build hashes, all repeated runs and ELF metadata. The default
guest CPU did not advertise `nx`: `GNU_STACK RW` is an ELF request, not evidence
of hardware-enforced execution prevention in this VM.

Earlier exploratory baseline (not a matched modern VM capture):

| Property | Legacy 32-bit | Modern x86-64 |
|---|---|---|
| Distribution | Debian 7.11 | Ubuntu 26.04.1 LTS |
| Architecture | i686 | x86_64 |
| Kernel | 3.2.0-4-686-pae | host kernel |
| GCC | Debian 4.7.2-5 | Ubuntu 15.2.0-16ubuntu1 |
| Binutils/readelf | GNU Binutils 2.22 | GNU Binutils 2.46 |
| ASLR setting | `2` | `2` |

Observed comparison:

| Question | Legacy 32-bit | Modern x86-64 |
|---|---|---|
| Is the default binary PIE? | no: `EXEC (Executable file)` | yes: `DYN (Position-Independent Executable file)` |
| Does `mitigation_no_pie` stay at a stable text address? | yes: `main` stayed at `0x80484db` across three runs | yes: `main` stayed at `0x401223` across three runs |
| Does the hardened binary import `__stack_chk_fail`? | yes | yes |
| Does the hardened binary contain `GNU_RELRO`? | yes | yes |
| Does the hardened binary use `BIND_NOW`? | yes | yes |
| Is `GNU_STACK` non-executable? | yes: `RW`, not `RWE` | yes: `RW`, not `RWE` |

Legacy address samples:

```text
mitigation_default:  0x80484db -> 0x80484db -> 0x80484db
mitigation_hardened: 0x804857d -> 0x804857d -> 0x804857d
mitigation_no_pie:   0x80484db -> 0x80484db -> 0x80484db
```

Modern address samples:

```text
mitigation_default:  0x5ffb89fc4227 -> 0x61f4b95ea227 -> 0x6188f1ad0227
mitigation_hardened: 0x5c4182ea6227 -> 0x57aae1a94227 -> 0x558f6224e227
mitigation_no_pie:   0x401223 -> 0x401223 -> 0x401223
```

## Security Meaning

Classical stack-smashing examples often assume a stable code address, a writable
control target and executable injected bytes. A modern baseline usually removes
at least one of those assumptions. That does not prove a program is safe, but it
changes the required primitive from "overwrite and jump" toward a chain such as
information disclosure plus code-reuse, or toward fixing the memory-safety bug
before control-flow redirection becomes relevant.
