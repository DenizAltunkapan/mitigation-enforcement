# Lab 09 Results — 18 November 2026

The RELRO GOT-overwrite experiment was captured in two distinct software environments:
an Ubuntu x86-64 review host and a Debian 13 x86-64 VM. Each environment probes
two cases three times each (6 trials per environment, **12 trials** total). The
operator label (`host` / `modern`) identifies the measurement run, not an
automatic attestation.

## Environment and provenance

| Property | Host review environment | Modern VM |
|---|---|---|
| OS / Distribution | Ubuntu 26.04.1 LTS (x86-64) | Debian GNU/Linux 13 (trixie) (x86-64) |
| Kernel | Linux 7.0.0-43-generic | Linux 6.12.105+deb13-amd64 |
| Compiler | GCC 15.2.0 (Ubuntu 15.2.0-16ubuntu1) | GCC 14.2.0 (Debian 14.2.0-19) |
| Assembler / Linker | GNU Binutils 2.46 | GNU Binutils 2.44 |
| C library | glibc 2.43 | glibc 2.41 |

The rows are reproduced from the committed [portable evidence](evidence/2026-11-18.json).
The two environments differ in compiler, linker, C library and kernel; partial
RELRO redirects and full RELRO faults in both, so the contrast is not specific to
one toolchain.

> Provenance note: both the host and the modern-VM captures in this file were
> recorded on 2026-11-18 under the environments pinned in
> [`research/environments.lock.json`](../../research/environments.lock.json).
> They were produced concurrently with the [pre-registration](../../research/plan.yaml),
> not provably after it, so they are **exploratory/pilot** captures, not a
> confirmatory dataset (see the pre-registration for the confirmatory protocol).
> Earlier host-only captures from this lab's first measurement were superseded
> by this dated, two-environment recapture.

## Observed outcomes

| Case | Linker | Result (3/3) |
|---|---|---|
| `partial` | `-z relro -z lazy` | `TARGET: GOT call redirected`, status `42` |
| `full` | `-z relro -z now` | `SIGSEGV` (`-11`), marker never printed |

Each case was identical across its three repeats. The `puts` GOT slot was read
per binary from its own relocations (`got_full` and `got_partial` lay the GOT out
differently); both addresses are recorded in the evidence.

## Finding

| Claim | Result |
|---|---|
| Under partial RELRO the GOT is writable and the call redirects | yes (`partial` → 42) |
| Under full RELRO the GOT is read-only and the write faults | yes (`full` → SIGSEGV) |

The two builds differ only in the RELRO linker option, so the contrast isolates
RELRO as the deciding factor. Reaching the oracle under partial RELRO is
control-flow redirection through the GOT — a target distinct from the saved
return address used by the control-flow labs 05, 06 and 08. Full RELRO, the
configuration the binaries in Labs 05–08 already use, maps the GOT read-only and
turns the overwrite into a fault.

## Methodological boundaries

1. **White-box static address.** The GOT slot comes from the local non-PIE build
   artifacts, not from a leak. A PIE target would first need the disclosure
   studied in Lab 06.
2. **One slot, one call.** A single GOT entry is overwritten and one call is
   triggered; this is not a full PLT/GOT ROP attack or a lazy-binding race.
3. **A loader/linker property.** The result is about where the dynamic linker
   maps the GOT, not a CPU feature; it says nothing about CET, canaries or NX.
4. **No control-flow claim beyond the redirect.** Reaching the oracle shows a
   redirected in-binary call, not arbitrary code execution or an attack on a real
   system.
5. **x86-64 only.** No i386 comparison is attempted here.

## Evidence and reproduction

[Portable text evidence](evidence/2026-11-18.json) contains all 12 observations
across both environments, each case's stdout and stderr, signed return codes, the
GOT-slot addresses, the finding, tool versions, the build command, and source and
binary hashes with the
full capture manifest hash. Regenerate a capture and the portable evidence with:

```bash
python3 scripts/capture-relro.py host /tmp/relro-host
python3 scripts/export-relro.py /tmp/relro-host --output /tmp/relro.json
```

The exporter verifies the complete capture manifest and artifact coverage before
writing. Checksums establish internal consistency relative to the manifest; they
do not authenticate who ran the experiment.
