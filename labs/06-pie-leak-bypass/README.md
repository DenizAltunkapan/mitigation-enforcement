# Lab 06 - Defeating PIE With an Information Leak

Research question: Lab 05 showed that a hardcoded target address faults under
PIE and ASLR because the per-process text base is unknown. Given a controlled
disclosure of one code pointer in the same process, does the saved-return
overwrite that failed in Lab 05 now reach its target, and does an explicit
bounds check still prevent it?

This is a local, white-box systems-security experiment on x86-64 Linux. Run it
as an ordinary user inside a disposable VM or on a local review host. The
overflow has undefined behavior in C; its outcome is an empirical observation
for a specific compiler, ABI and binary configuration. ASLR is left at the
host's setting and is required: the result is only meaningful while the text
segment is randomized.

## Concepts

The experiment uses a separate program under PIE build settings comparable to
Lab 05's `overwrite_pie`, keeps the same bug class, and adds one primitive — a
pointer disclosure:

1. **Programming error (memory-safety bug):** `overflow()` in
   [src/pie_leak.c](src/pie_leak.c) reads an attacker-chosen byte count into a
   32-byte stack buffer without an upper bound unless `FIXED` is defined. This is
   the same bug class as Lab 05.
2. **Disclosure primitive (the leak):** the program prints the runtime address of
   `reference_symbol()`, a code pointer into the randomized PIE text segment. It
   stands in for a real bug class (a format-string `%p`, an uninitialized read)
   without modelling a specific CVE. The disclosure and the overflow happen in
   one process, so the base the attacker learns is the base the overflow runs
   against.
3. **Measurement oracle (`redirect_target()`):** an unreachable, side-effect-free
   function that prints `TARGET: control flow redirected` and exits with status
   `42`. As in Lab 05, using an in-binary oracle isolates instruction-pointer
   redirection from code injection and from external libc or ROP chains.

`reference_symbol()` and `redirect_target()` share the text segment, so their
link-time distance is constant and the same in every process. From the single
leaked pointer the attacker computes the runtime target:

```text
redirect_target_runtime = leaked(reference_symbol) + (redirect_target - reference_symbol)
```

The link-time delta `(redirect_target - reference_symbol)` is read from the local
build artifacts with `nm` and `objdump`, exactly as Lab 05 reads static
addresses. That delta is not an information disclosure; only the runtime base is.

## Why the leak and the overflow must share a process

Under ASLR the text base differs between executions. Leaking from one process and
overflowing another feeds a stale base and faults — which is precisely the Lab 05
negative result. A realistic attacker chains a leak and a memory-corruption bug
within one session. The program models that: `pie_leak session` discloses the
pointer and then takes the overflow input in the same run.

## Cases

Both binaries are built position-independent (`ET_DYN`, `-fPIE -pie`) from
[src/pie_leak.c](src/pie_leak.c) with the same base flags
(`-O0 -g -fno-omit-frame-pointer -fno-optimize-sibling-calls -U_FORTIFY_SOURCE -fno-stack-protector`
and `-Wl,-z,relro,-z,now,-z,noexecstack`). Stack protection is off so the studied
variable is the leak, not the canary already covered in Labs 04 and 05.

| Case | Binary | Base used for the target | Observed outcome |
|---|---|---|---|
| `bypass` | `pie_bypass` | runtime base from the same-process leak | **Redirected:** enters `redirect_target()`, prints the marker, exits with status `42` |
| `stale` | `pie_bypass` | a base leaked from a different process (the Lab 05 stale-address situation) | **Address fault:** control reaches the stale address range and faults, `SIGSEGV` (`-11`), marker never printed |
| `fixed` | `pie_fixed` (`-DFIXED`) | runtime base from the same-process leak | **Prevented pre-write:** the bounds check rejects the input, exits with status `2` |

The `stale` case is the negative control: the only difference from `bypass` is the
base. The collector obtains the stale base from a *separate* `leak`-only run of
the same binary (its raw output is kept as evidence) and attacks a fresh session
with it; under ASLR the two bases differ, and the collector asserts they do. It
then replays one stale attack under GDB and records the faulting instruction
pointer: it lies in the stale (wrong-process) text range and not in the attacked
process's own range, showing control was redirected to the stale address range
and faulted there rather than crashing incidentally. A `bypass` success and a
`stale` fault together show that the *current* process's leak — not the overflow
length, the payload shape, or any leaked base — is what enables redirection. The
`fixed` case shows that repairing the bug defeats the attack even when the leak
succeeds.

The payload reuses the Lab 05 structure: `saved-return offset` bytes of filler,
an 8-byte alignment `ret` gadget, then the 8-byte target address, all rebased to
the leaked runtime base. The alignment gadget satisfies the x86-64 ABI entry
invariant (`%rsp % 16 == 8`) exactly as documented in
[Lab 05](../05-return-address-overwrite/README.md#why-the-measured-x86-64-payload-uses-the-alignment_ret-gadget).

## Build and capture

Build the two variants locally:

```bash
make -C labs/06-pie-leak-bypass
```

### Automated evidence capture

Run the collector in a fresh output directory:

```bash
python3 scripts/capture-pie-leak.py host /tmp/pie-leak-host
```

The collector builds both binaries in an isolated directory, checks ELF headers
(`ET_DYN`, no `__stack_chk_fail`, `GNU_RELRO`, `BIND_NOW`, `GNU_STACK RW`),
measures the saved-return offset via GDB, reads the link-time reference/target
delta and an alignment `ret` gadget from the local artifacts, then runs the three
cases three times each (9 trials) with core dumps disabled. It requires ASLR to be
enabled, confirms the leaked base varies across runs, and replays one stale attack
under GDB to record where it faults (`stale-fault.json`). It writes
`observations.json`, `payload.json`, `SHA256SUMS` and `COMPLETE`. A failed or
unexpected run keeps its partial evidence without `COMPLETE`.

Export verified portable text evidence from one or more complete captures:

```bash
python3 scripts/export-pie-leak.py /tmp/pie-leak-host \
  --output /tmp/pie-leak.json
```

The exporter verifies the full manifest and exact artifact coverage, requires the
leaked base to have varied, and refuses to overwrite an existing JSON file. The
committed [portable evidence](evidence/) records a host capture and a Debian 13 VM capture.

## Attacker assumptions and limits

1. **The leak is assumed, not demonstrated against a specific bug.** The program
   discloses a code pointer explicitly. Real disclosures arise from distinct bugs
   (format strings, uninitialized reads, side channels); this lab does not model
   any particular one or its difficulty.
2. **Same-process chaining.** The result holds because the leak and the overflow
   share a process. It does not measure cross-process base prediction, partial
   overwrites, or defeating ASLR without a leak.
3. **One randomized object.** Only the main PIE executable's base is defeated
   here. Libraries, the stack and the heap have independent randomization that
   this lab does not address.
4. **No claim beyond redirection.** Reaching the in-binary oracle shows
   instruction-pointer control to one known in-binary address. It transfers
   control to an existing function; it does not demonstrate arbitrary or
   attacker-supplied code execution, a ROP chain, or an attack on a real system.

## Relation to the other labs

Lab 05 established that PIE+ASLR turns the hardcoded-address overwrite into a
fault. Lab 06 keeps that binary configuration and shows the fault was an
information gap, not a structural guarantee: one leaked pointer restores the
redirection, while the bounds check from Lab 05 still prevents it. The legacy
i386 toolchain comparison discussed in Lab 05 remains open here too; this lab is
measured only on x86-64.
