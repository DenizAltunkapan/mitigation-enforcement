# Lab 10 Results — 16 November 2026

The format-string experiment ran on an Ubuntu x86-64 review host. Each capture
probes four cases three times each (12 trials). The operator label (`host`)
identifies the measurement run, not an automatic attestation. A Debian 13 VM
replication is planned and not yet recorded.

## Environment and provenance

| Property | Host review environment |
|---|---|
| OS / Distribution | Ubuntu 26.04.1 LTS (x86-64) |
| Compiler | GCC 15.2.0 (Ubuntu 15.2.0-16ubuntu1) |
| Assembler / Linker | GNU Binutils 2.46 |
| C library | glibc 2.43 |

The rows are reproduced from the committed [portable evidence](evidence/2026-11-16.json).

## Observed outcomes

| Case | Build | Input | Result (3/3) |
|---|---|---|---|
| `leak` | plain, `-O2` | `%p` walk | the planted numeric marker appears, status 0 |
| `write` | plain, `-O2` | `AAAA%n` | test variable becomes `4`, status `42` |
| `fortify` | `_FORTIFY_SOURCE=2`, `-O2` | `AAAA%n` | `SIGABRT` (`-6`), `%n in writable segments detected` (wording is glibc-version dependent) |
| `fixed` | constant format, `-O2` | `AAAA%n` | input printed literally, status `0` |

Each case was identical across its three repeats. The fortified binary imports
`__printf_chk`; the plain binary imports plain `printf`.

## Finding

| Claim | Result |
|---|---|
| A format string discloses stack memory (the planted marker) | yes (`leak`) |
| `%n` changes the supplied local test variable | yes (`write` → 42) |
| FORTIFY rejects the `%n` write before it is attempted | yes (`fortify` → SIGABRT) |
| A constant format string removes the conversion | yes (`fixed` → literal output) |

The `write` and `fortify` cases use the same `AAAA%n` input against `-O2` builds
differing only in `_FORTIFY_SOURCE`. The write-versus-abort contrast isolates the
glibc check. The pointer to the test variable is supplied by the program; the
attacker does not choose an arbitrary destination. The disclosure is not the
PIE-base pointer leak assumed in Lab 06. The fixed-format build treats the same
input as data and removes the vulnerability rather than blocking one conversion.

## Methodological boundaries

1. **The primitive, not a targeted exploit.** The lab shows a disclosure and a
   write to a program-supplied pointer. An arbitrary destination without that
   pointer is out of scope.
2. **A glibc build-time property.** The result is about `_FORTIFY_SOURCE` and the
   writable-format `%n` check in this glibc, not a CPU feature.
3. **One disclosure, one local write.** The lab does not chain a leak into a targeted
   write, which is how a real format-string exploit proceeds.
4. **No real target.** The marker and the local write are synthetic and local.
5. **x86-64 only.** No i386 comparison is attempted here.

## Evidence and reproduction

[Portable text evidence](evidence/2026-11-16.json) contains all twelve observations,
each case's stdout and stderr, signed return codes, the leak and write formats,
the finding, tool versions, the build command, and source and binary hashes with
the full capture manifest hash. Regenerate a capture and the portable evidence
with:

```bash
python3 scripts/capture-format-string.py host /tmp/format-string-host
python3 scripts/export-format-string.py /tmp/format-string-host --output /tmp/format-string.json
```

The exporter verifies the complete capture manifest and artifact coverage before
writing. Checksums establish internal consistency relative to the manifest; they
do not authenticate who ran the experiment.
