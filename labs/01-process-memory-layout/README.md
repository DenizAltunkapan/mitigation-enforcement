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

## Recorded comparison

The [verified Debian 7 / Debian 13 comparison](../../docs/BASELINE-COMPARISON.md)
uses identical sources, Makefiles, collector and recorded build variables.
Each environment has three runs of this program:

| Observation | Debian 7 i386 | Debian 13 amd64 |
|---|---|---|
| Default ELF type | `EXEC` | `DYN` (PIE) |
| `main` across three runs | fixed at `0x8048688` | changes in all three runs |
| Heap and stack placement | changes in all three runs | changes in all three runs |
| libc executable mapping | changes in all three runs | changes in all three runs |

The legacy `printf from libc` pointer lies in the executable mapping, while
its modern counterpart lies in the libc mapping. Use `/proc/self/maps` to
identify the actual libc mapping rather than treating that pointer as its base.

The comparison report links all runtime transcripts, ELF metadata and source
hashes. The legacy installation was recovered; this is not a clean-install
validation or an experiment isolating architecture from toolchain differences.
Three samples do not measure ASLR entropy.

## Security Meaning

Classical exploit paths often assume predictable addresses. If stack, heap,
libc or the program text move every run, an attacker needs another primitive,
usually an information leak, before reliable control-flow redirection becomes
possible.
