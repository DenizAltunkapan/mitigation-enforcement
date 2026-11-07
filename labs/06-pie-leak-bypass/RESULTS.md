# Lab 06 Results — 7 November 2026

The PIE-leak experiment was executed on an Ubuntu x86-64 review host. Each capture
runs three cases three times each (9 trials): a same-process leak-and-rebase
(`bypass`), the Lab 05 stale-address situation (`stale`), and the repaired binary
(`fixed`). A Debian 13 VM replication is planned and not yet recorded; the
operator label (`host`) identifies the measurement run, not an automatic
attestation.

## Environment and provenance

| Property | Host review environment |
|---|---|
| OS / Distribution | Ubuntu 26.04.1 LTS (x86-64) |
| Kernel | Linux 7.0.0-42-generic |
| Compiler | GCC 15.2.0 (Ubuntu 15.2.0-16ubuntu1) |
| Assembler / Linker | GNU Binutils 2.46 |
| C library | glibc 2.43 |
| Debugger | GNU GDB 17.1 (Ubuntu 17.1-2ubuntu1) |
| ASLR setting | `2` (`randomize_va_space`) |

The table rows are reproduced from the committed
[portable evidence](evidence/2026-11-07.json). The capture refuses to run with
ASLR disabled and verifies that the leaked text base varied across the nine runs.

## Observed outcomes

| Case | Binary | Base | Safe behavior | Attack behavior (3/3) |
|---|---|---|---|---|
| `bypass` | `pie_bypass` | same-process leak | n/a | 3/3 target reached, status `42` |
| `stale` | `pie_bypass` | base leaked from a different process | n/a | 3/3 `SIGSEGV` (`-11`), target not reached |
| `fixed` | `pie_fixed` | same-process leak | rejects oversized input | 3/3 rejected pre-write, status `2` |

All nine runs disclosed a distinct `reference_symbol()` address (9 distinct
bases), confirming ASLR randomized the text segment between executions. The
`bypass` case nevertheless redirected every time, because the target was rebased
to each run's leaked base.

## Mechanism

- **Saved-return offset:** GDB measured 40 bytes from the buffer to the saved
  return address in `pie_bypass`, identical to the Lab 05 `overwrite_plain`
  layout. The payload is 56 bytes: 40 filler bytes, an 8-byte alignment `ret`
  gadget, then the 8-byte rebased `redirect_target` address.
- **Leak:** `reference_symbol()`'s runtime address discloses the text base. With
  the link-time delta `redirect_target - reference_symbol` (read from the local
  build artifacts), the attacker computes the runtime target address.
- **`bypass`:** the rebased target is mapped and executable in this process, so
  the final `ret` transfers control into `redirect_target()` with
  `%rsp % 16 == 8`, satisfying the x86-64 ABI entry invariant.
- **`stale`:** a base leaked from a separate process points the target at the
  stale address range, reproducing the Lab 05 `SIGSEGV`. The collector confirms
  the stale and session bases differ, and a GDB replay records the faulting
  instruction pointer inside the stale text range and outside the attacked
  process's own range — so control was redirected to the stale address and
  faulted there. The only change from `bypass` is which process's base is used,
  which isolates the same-process leak as the enabling factor.
- **`fixed`:** the bounds check `count > sizeof(buffer)` rejects the input before
  the write, so the leak does not matter.

## Methodological boundaries

1. **The leak is assumed.** The program discloses a code pointer explicitly; the
   result does not measure the difficulty of obtaining such a disclosure from a
   real bug.
2. **Same-process chaining only.** The experiment does not address cross-process
   base prediction or defeating ASLR without a leak.
3. **One randomized object.** Only the main executable's text base is defeated;
   library, stack and heap randomization are independent and out of scope.
4. **No claim beyond redirection.** Reaching the in-binary oracle demonstrates
   instruction-pointer control to one known in-binary address. It runs an
   existing function; it is not arbitrary or attacker-supplied code execution,
   and not an attack on a real system.

## Evidence and reproduction

[Portable text evidence](evidence/2026-11-07.json) contains all nine
observations, each run's leak line, stdout and stderr, signed return codes, tool
versions, build commands, payload metadata, source and binary hashes, and the
full capture manifest hash. Regenerate a capture and the portable evidence with:

```bash
python3 scripts/capture-pie-leak.py host /tmp/pie-leak-host
python3 scripts/export-pie-leak.py /tmp/pie-leak-host --output /tmp/pie-leak.json
```

The exporter verifies the complete capture manifest and artifact coverage before
writing. Checksums establish internal consistency relative to the manifest; they
do not authenticate who ran the experiment.
