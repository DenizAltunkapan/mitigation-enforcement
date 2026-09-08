# Lab 01 - Process Memory Layout

This lab observes where a normal C process places code, globals, heap memory,
stack memory and shared libraries.

It answers the first exploitation question:

```text
If a program gives me an address or lets me overwrite memory, where is that
memory in the process?
```

## Concepts

Typical process regions:

```text
text      program code
data      initialized global variables
bss       zero-initialized global variables
heap      dynamic allocations such as malloc
stack     local variables, call frames and return addresses
libc      shared C runtime mapped into the process
ld.so     dynamic loader
```

Modern systems usually randomize several of these locations with ASLR. A
position-independent executable also lets the program's own code move.

## Build

```bash
make
```

The default build keeps debug symbols and disables optimization so the output
is easier to inspect:

```text
-O0 -g -fno-omit-frame-pointer
```

## Run

```bash
./memory_layout
```

Run it multiple times:

```bash
for i in 1 2 3; do ./memory_layout | sed -n '1,12p'; echo; done
```

## Inspect

Check whether ASLR is enabled:

```bash
cat /proc/sys/kernel/randomize_va_space
```

Common values:

```text
0  disabled
1  conservative randomization
2  full randomization
```

Check whether the binary is position independent:

```bash
file ./memory_layout
readelf -h ./memory_layout | grep Type
```

Useful `readelf` types:

```text
EXEC  traditional non-PIE executable
DYN   position-independent executable or shared object
```

## What To Compare

Measured baseline:

| Property | Historical LiveCD | Modern VM |
|---|---|---|
| Distribution | Ubuntu 7.04 (from LiveCD rootfs) | Debian GNU/Linux 13 (trixie) |
| Architecture | i386 | x86_64 |
| Kernel | 2.6.20-15-generic | 6.12.105+deb13-amd64 |
| GCC | 4.1.2 package in LiveCD manifest | Debian 14.2.0-19 |
| GDB | 6.6 package in LiveCD manifest | Debian 16.3-1 |
| glibc | 2.5 package in LiveCD manifest | 2.41-12+deb13u3 |
| ASLR setting | configured as `kernel.randomize_va_space=0` in LiveCD rootfs | `2` |
| NX support | not measured yet from interactive LiveCD shell | supported |

The preferred scriptable legacy baseline is the Debian 7 i386 VM created by
`scripts/setup-legacy-vm.sh`. Fill its runtime values after the VM install
completes and SSH on `localhost:2222` works.

Observed comparison:

| Question | Legacy 32-bit | Modern x86-64 |
|---|---|---|
| Are addresses 32-bit or 64-bit sized? | 32-bit expected from i386 LiveCD; run pending | 64-bit addresses observed |
| Does `main` move between runs? | run pending | yes: `0x55bc98c88150` -> `0x564ec8d08150` |
| Does the stack move between runs? | run pending | yes: `0x7ffd5a38ebf4` -> `0x7fff71153ca4` |
| Does the heap move between runs? | run pending | yes: `0x55bcbdaab2a0` -> `0x564f049e42a0` |
| Does libc move between runs? | run pending | yes: `0x7f7e9d331900` -> `0x7f50a0eb8900` |
| Is the binary PIE by default? | run pending | yes: `DYN (Position-Independent Executable file)` |

Legacy note: the LiveCD boots under QEMU and exposes kernel output over serial,
but did not provide an interactive serial shell in the tested boot path. Use
the scriptable Debian 7 VM for the final legacy runtime measurements.

## Security Meaning

Classical exploit paths often assume predictable addresses. If stack, heap,
libc or the program text move every run, an attacker needs another primitive,
usually an information leak, before reliable control-flow redirection becomes
possible.
