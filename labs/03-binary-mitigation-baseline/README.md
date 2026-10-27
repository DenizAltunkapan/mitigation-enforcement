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

## Recorded comparison

The [verified Debian 7 / Debian 13 comparison](../../docs/BASELINE-COMPARISON.md)
contains three runs and full ELF metadata for each variant in each environment.
C sources, Makefiles, collector and build-variable values match; actual compiler
versions and supported no-PIE options differ and are recorded in the build logs.

| Observation | Debian 7 i386 | Debian 13 amd64 |
|---|---|---|
| Default / hardened ELF type | `EXEC` / `EXEC` | `DYN` / `DYN` |
| Default / hardened text address | stable / stable | moving / moving |
| No-PIE `main` across three runs | fixed at `0x80484db` | fixed at `0x4011ac` |
| Hardened guard symbol | `__stack_chk_fail` imported | `__stack_chk_fail` imported |
| Hardened RELRO / NOW | present / present | present / present |
| Hardened stack request | `GNU_STACK RW` | `GNU_STACK RW` |
| CPU advertises NX | no | yes |

The no-PIE contrast within the modern environment is evidence that ASLR being
set to 2 does not by itself relocate non-PIE text. The default-versus-hardened
pair changes multiple protections, so it cannot isolate one mitigation's effect.

Neither a non-executable-stack ELF request nor a CPU feature flag establishes
runtime execution-permission enforcement for a particular memory region. This
lab performs no execution-permission test. In particular, the selected legacy
QEMU CPU does not advertise NX. Guard symbols also do not prove protection of
a specific function; Lab 04 provides a separate runtime stack-guard experiment.

## Security Meaning

Classical stack-smashing examples often assume a stable code address, a writable
control target and executable injected bytes. A modern baseline usually removes
at least one of those assumptions. That does not prove a program is safe, but it
changes the required primitive from "overwrite and jump" toward a chain such as
information disclosure plus code-reuse, or toward fixing the memory-safety bug
before control-flow redirection becomes relevant.
