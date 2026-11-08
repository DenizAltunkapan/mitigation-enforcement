# Lab 07 Results — 8 November 2026

The runtime execution-permission experiment ran on an Ubuntu x86-64 review host.
Each capture probes three page protections three times each (9 trials). The
operator label (`host`) identifies the measurement run, not an automatic
attestation. A Debian 13 VM replication is planned and not yet recorded.

## Environment and provenance

| Property | Host review environment |
|---|---|
| OS / Distribution | Ubuntu 26.04.1 LTS (x86-64) |
| Compiler | GCC 15.2.0 (Ubuntu 15.2.0-16ubuntu1) |
| Assembler / Linker | GNU Binutils 2.46 |
| C library | glibc 2.43 |
| CPU advertises NX | yes |

The rows are reproduced from the committed [portable evidence](evidence/2026-11-08.json),
which also contains the `oracle` disassembly used to confirm the probed bytes.

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

[Portable text evidence](evidence/2026-11-08.json) contains all nine
observations, each mode's stdout and stderr, signed return codes, the oracle
disassembly, tool versions, the build command, the finding, and source and binary
hashes with the full capture manifest hash. Regenerate a capture and the portable
evidence with:

```bash
python3 scripts/capture-wx.py host /tmp/wx-host
python3 scripts/export-wx.py /tmp/wx-host --output /tmp/wx.json
```

The exporter verifies the complete capture manifest and artifact coverage before
writing. Checksums establish internal consistency relative to the manifest; they
do not authenticate who ran the experiment.
