# Lab 07 Results — 18 November 2026

The runtime execution-permission experiment was captured in two distinct software
environments: an Ubuntu x86-64 review host and a Debian 13 x86-64 VM. Each
environment probes three page protections three times each (9 trials per
environment, **18 trials** total). The operator label (`host` / `modern`)
identifies the measurement run, not an automatic attestation.

## Environment and provenance

| Property | Host review environment | Modern VM |
|---|---|---|
| OS / Distribution | Ubuntu 26.04.1 LTS (x86-64) | Debian GNU/Linux 13 (trixie) (x86-64) |
| Kernel | Linux 7.0.0-43-generic | Linux 6.12.105+deb13-amd64 |
| Compiler | GCC 15.2.0 (Ubuntu 15.2.0-16ubuntu1) | GCC 14.2.0 (Debian 14.2.0-19) |
| Assembler / Linker | GNU Binutils 2.46 | GNU Binutils 2.44 |
| C library | glibc 2.43 | glibc 2.41 |
| CPU advertises NX | yes | yes |

The rows are reproduced from the committed [portable evidence](evidence/2026-11-18.json),
which also contains the `oracle` disassembly used to confirm the probed bytes.
The two environments differ in compiler, linker, C library and kernel, so the
result holds across two distinct toolchains, not one.

> Provenance note: both the host and the modern-VM captures in this file were
> recorded on 2026-11-18 under the environments pinned in
> [`research/environments.lock.json`](../../research/environments.lock.json).
> They were produced concurrently with the [pre-registration](../../research/plan.yaml),
> not provably after it, so they are **exploratory/pilot** captures, not a
> confirmatory dataset (see the pre-registration for the confirmatory protocol).
> Earlier host-only captures from this lab's first measurement were superseded
> by this dated, two-environment recapture.

## Observed outcomes

| Mode | Protection | Result (3/3) |
|---|---|---|
| `rw` | read + write | SIGSEGV (`-11`), marker never printed |
| `rx` | read + exec | `CALLED 42`, status 0 |
| `rwx` | read + write + exec | `CALLED 42`, status 0 |

Each mode was identical across its three repeats. The same oracle bytes that
faulted under `rw` ran under `rx`, differing only in the execute bit.

## Finding

| Claim | Result |
|---|---|
| A non-executable page faults when its bytes are called | yes |
| The identical bytes run once the page is executable | yes |
| A writable + executable mapping was allowed | yes |
| A writable + executable mapping was rejected | no |

In this anonymous mapping, on this host, a missing execute permission blocked the
call (`rw` faulted) while the identical bytes ran once execute was granted (`rx`),
so the page's execute permission, not the bytes or the mapping identity, decided
whether the code ran: NX was in effect here. The `rwx` result shows that W^X was
**not** enforced on this host — the kernel permitted a writable-and-executable
mapping. NX (a CPU feature) and W^X (a software policy) are distinct guarantees,
and only the first held in this measurement. The claim is scoped to this
anonymous-mapping probe on this host, not to loaded segments, stacks or heaps, or
to other kernels (see the boundaries below).

## Methodological boundaries

1. **Policy, not universality.** The `rwx` outcome is this host's policy. An LSM
   (SELinux `execmem`), a hardened or `pax` kernel, or a seccomp filter can
   reject a writable-executable mapping. A different host may record the opposite
   `rwx` result; both are valid observations of their environment.
2. **Anonymous mappings only.** The experiment measures `mmap`/`mprotect` page
   permissions, not the executable's own loaded segments or stack/heap execution
   specifically.
3. **No control-flow claim.** Reaching the oracle shows copied bytes executed
   under a permission; it is not an exploit and establishes nothing about
   redirecting a real program, which Labs 05 and 06 cover.
4. **x86-64 only.** No i386 comparison is attempted; the legacy environment's
   default QEMU CPU does not advertise NX (Lab 03).

## Evidence and reproduction

[Portable text evidence](evidence/2026-11-18.json) contains all 18 observations
across both environments, each mode's stdout and stderr, signed return codes, the
oracle disassembly, tool versions, the build command, the finding, and source and
binary hashes with the full capture manifest hash. Regenerate the host capture and the portable
evidence with:

```bash
python3 scripts/capture-wx.py host /tmp/wx-host
python3 scripts/export-wx.py /tmp/wx-host --output /tmp/wx.json
```

The exporter verifies the complete capture manifest and artifact coverage before
writing. Checksums establish internal consistency relative to the manifest; they
do not authenticate who ran the experiment.
