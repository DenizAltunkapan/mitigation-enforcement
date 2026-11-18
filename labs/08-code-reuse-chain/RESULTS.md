# Lab 08 Results — 18 November 2026

The code-reuse experiment was captured in two distinct software environments: an Ubuntu
x86-64 review host and a Debian 13 x86-64 VM. Each environment runs three
control-flow cases three times each (9 process trials per environment,
**18 process trials** total) and measures the NX control separately under GDB. The
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
| Debugger | GNU GDB 17.1 (Ubuntu 17.1-2ubuntu1) | GNU GDB 16.3 (Debian 16.3-1) |

The rows are reproduced from the committed [portable evidence](evidence/2026-11-18.json).
The two environments differ in compiler, linker, C library and kernel; the
ordered chain reaches the oracle and the stack jump faults under NX in both, so
the result is not specific to one toolchain.

> Provenance note: both the host and the modern-VM captures in this file were
> recorded on 2026-11-18 under the environments pinned in
> [`research/environments.lock.json`](../../research/environments.lock.json).
> They were produced concurrently with the [pre-registration](../../research/plan.yaml),
> not provably after it, so they are **exploratory/pilot** captures, not a
> confirmatory dataset (see the pre-registration for the confirmatory protocol).
> Earlier host-only captures from this lab's first measurement were superseded
> by this dated, two-environment recapture.

## Observed outcomes

| Case | Payload | Result (3/3) |
|---|---|---|
| `chain` | `stage_one` → `stage_two` → `oracle` | `ONE`, `TWO`, marker; status `42` |
| `partial` | `stage_two` → `oracle` | marker, status `43` (stage_one never ran) |
| `fixed` | bounds-checked build | rejected pre-write, status `2` |

The NX control is measured separately. A stack address from one process is wrong
for another under ASLR, so its outcome is measured in-process under GDB with
randomization disabled: the overflow points the saved return at the live stack
buffer, and GDB records that the fault instruction pointer equals that buffer and
lies inside the non-executable `[stack]` mapping (`rw-p`). The `SIGSEGV` is
therefore a blocked attempt to execute bytes on the non-executable stack, not a
jump to an unmapped address.

Each case was identical across its three repeats. The saved-return offset was 40
bytes, matching the Lab 05 layout; the chain payload interleaves a `ret` gadget
before each reused function for 16-byte stack alignment.

## Finding

| Claim | Result |
|---|---|
| NX blocks execution of stack bytes | yes — fault PC equals the stack buffer, inside the non-executable `[stack]` mapping |
| Reuse of already-executable code redirects control flow despite NX | yes (`chain` → 42) |
| The chain genuinely sequences gadgets in order | yes (`partial` → 43) |
| A bounds check prevents the redirection | yes (`fixed` → 2) |

The NX control and the `chain` case hold in the *same binary under the same
enforced NX*: a jump onto the non-executable stack faults where its bytes would
execute, yet control flow is redirected through functions that were already
mapped executable. This is the classical move from code injection to code reuse.
NX did not fail; it stayed enforced, and the attack avoided it by not placing new
code. As in Labs 04–06, the only change that *prevented* the effect rather than
redirecting it was the bounds-check repair.

## Methodological boundaries

1. **White-box static addresses.** Gadget and `ret` addresses come from the local
   non-PIE build artifacts, not from a leak. A PIE target would first require the
   disclosure studied in Lab 06.
2. **A minimal ordered chain.** Two in-binary gadgets are sequenced to demonstrate
   ordered reuse; this is not a libc ROP chain, a call to `system`, or a real
   payload. The destination is a harmless in-binary oracle.
3. **NX stayed enforced.** The result is reuse *despite* NX, confirmed by the
   in-process stack-execution fault in the same binary — not a failure of NX.
4. **No control-flow-integrity defense.** CET/`-fcf-protection` is disabled to
   isolate the overwrite; a shadow stack or indirect-branch tracking would change
   the outcome and is out of scope here.
5. **x86-64 only.** No i386 comparison is attempted (see Lab 03 on the legacy
   environment's NX limitation).

## Evidence and reproduction

[Portable text evidence](evidence/2026-11-18.json) contains all 18 process
observations across both environments, each case's stdout and stderr, signed
return codes, the payload metadata, the NX fault measurement, the finding, tool
versions, the build command, and source and binary hashes with the full capture
manifest hash.
Regenerate a capture and the portable evidence with:

```bash
python3 scripts/capture-code-reuse.py host /tmp/code-reuse-host
python3 scripts/export-code-reuse.py /tmp/code-reuse-host --output /tmp/code-reuse.json
```

The exporter verifies the complete capture manifest and artifact coverage before
writing. Checksums establish internal consistency relative to the manifest; they
do not authenticate who ran the experiment.
