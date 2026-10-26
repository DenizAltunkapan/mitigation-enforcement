# Lab 04 - Stack Canary: Detection Versus Repair

Research question: within one environment, does enabling a stack guard detect
an overwrite of a local buffer before the function returns, and does checking
the input size prevent the overwrite itself?

This is a deliberately unsafe, local C example. Input consists only of repeated
`A` bytes. It contains no shellcode, target address, address discovery or exploit
chain. Run it as an ordinary user inside a lab VM. The overflow has undefined
behavior; its outcome is an observation for a particular build, not a C language
guarantee.

## Controlled comparison

All three binaries use the same source, compiler, optimization level, linker
flags and environment. The unprotected/canary pair differs only in the stack
protector compiler flag. ASLR is left at its existing setting. PIE follows the
compiler default and must be checked in the captured ELF data. RELRO/NOW and a
non-executable stack are requested for all variants. Fortified libc checks are
suppressed consistently to avoid attributing their effects to the stack guard.
Do not add unrelated hardening overrides when interpreting this comparison.

| Binary | Stack protector | Bounds check | Purpose |
|---|---|---|---|
| `stack_unprotected` | explicitly disabled | absent | observe the unsafe operation without the guard |
| `stack_canary` | all functions | absent | detect corruption when leaving the function |
| `stack_fixed` | all functions | checks size before reading | prevent the out-of-bounds write |

`safe` requests 16 bytes into a 32-byte buffer; `overflow` requests 128 bytes.
The input loop handles short reads and interrupted system calls. EOF before the
requested count is an error. A partial oversized input can already corrupt the
vulnerable variants; a short-read error does not make those variants safe.
The fixed binary rejects oversized requests before reading any bytes.

## Build and capture

Build with GCC and Binutils on x86 Linux:

```bash
make -C labs/04-stack-canary
```

The dedicated capture builds in a new directory, leaving source-tree binaries
untouched. From the repository root, on a Linux host with Python 3.8+:

```bash
python3 scripts/capture-stack-canary.py host /tmp/canary-host
# Repeat with optimization; use a distinct output directory.
CFLAGS='-O2 -g -Wall -Wextra -fno-omit-frame-pointer' \
  python3 scripts/capture-stack-canary.py host /tmp/canary-host-o2
```

The parent directory must exist. Existing directories, files and symlinks are
never overwritten. `CC` selects one compiler executable; `CFLAGS` and `LDFLAGS`
are recorded and passed to Make. Each binary/input pair runs three times with
a timeout and core dumps disabled. The script requires GCC-compatible flags,
GNU Make, `readelf`, `objdump`, `getconf` and Linux `/proc`.

The `legacy` and `modern` labels are operator supplied, not environment checks.
Debian 7's stock Python is too old for this collector. Build/run the C lab there
with its existing compiler and collect evidence externally, or explicitly record
a separately installed compatible Python. Do not present host captures as VM
measurements. Labs 01–03 keep their separate `capture-baseline.sh` workflow.

Evidence includes source and Makefile copies, the collector, exact build
commands, compiler/libc/OS versions, ASLR, binaries, ELF metadata, disassembly,
exact input bytes, stdout/stderr and signed subprocess return codes in
`observations.json`. Negative return codes identify signals, rather than shell
exit-code conventions. `SHA256SUMS` covers all artifacts except itself and
`COMPLETE`. Verify it inside the capture directory using `sha256sum -c SHA256SUMS`.
`COMPLETE` appears only after every required check passes. Failed captures remain
available for diagnosis; do not use an incomplete capture as a successful result.

## Interpretation

| Input | Unprotected | Canary | Fixed |
|---|---|---|---|
| 16 bytes | normal return required | normal return required | normal return required |
| 128 bytes | record outcome; no required behavior | expect `SIGABRT`, glibc stack-smashing diagnostic, no return marker | reject with status 2 before copying |

The collector deliberately checks the glibc diagnostic and `SIGABRT`; it fails
on platforms whose behavior differs, retaining the raw evidence for review.
The ELF symbol check establishes guard support; inspect `copy_input` in the
disassembly to locate the actual guard check. A diagnostic and termination on
the vulnerable path provide runtime evidence beyond an imported symbol alone.

`copy completed` means that the read finished. Only `returned from copy_input`
shows that execution reached the caller afterward. A crash without a canary
proves neither arbitrary code execution nor a reliable exploit. A canary abort
means the invalid write has already happened; it does not fix the bounds error.
The fixed variant's rejection is the actual repair for this input path.

Compare historical and modern systems as separate experiments. Within each,
compare the controlled binary pair first. Cross-system differences also include
architecture, ABI, compiler and libc, so they cannot be attributed solely to the
stack guard. This lab does not establish effects of NX, PIE/ASLR or RELRO on an
exploit, nor a bypass of those protections.

## Recorded results

Export one or more complete captures to a new portable text snapshot:

```bash
python3 scripts/export-stack-canary.py /tmp/canary-host /tmp/canary-host-o2 \
  --output /tmp/canary-evidence.json
```

The exporter checks manifest hashes and exact artifact coverage before writing.
It rejects incomplete or modified captures and preserves existing output files.
The JSON includes all 18 observations per capture, stdout/stderr, build commands,
tool versions and hashes. Keep the full captures for binary/disassembly review;
the snapshot is selected text evidence, not an authenticity guarantee.

See [the 25 October 2026 results](RESULTS.md) for host and Debian VM observations,
selected raw text evidence, exact toolchain versions and the legacy limitation.

## Validation

```bash
python3 -m unittest discover -s tests -v
```

The tests exercise real builds at `-O0` and `-O2`, repeated safe/oversized
inputs, runtime guard detection, fixed rejection, invalid arguments, short input,
ELF properties, checksums, failed builds and preservation of existing evidence.
