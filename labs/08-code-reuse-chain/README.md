# Lab 08 - Code Reuse Under a Non-Executable Stack

Research question: Lab 07 measured that a non-executable page is not runnable,
which is what defeats classic stack shellcode. The standard answer is to reuse
code that is already executable. Under what conditions does a stack overflow
redirect control flow through a *chain* of existing in-binary functions while NX
stays in effect, and which repair prevents it?

This is a local, white-box systems-security experiment on x86-64 Linux. Run it
as an ordinary user on a review host or in a disposable VM. The overflow has
undefined behavior in C; its outcome is an empirical observation for a specific
compiler, ABI and binary configuration.

Framing, kept precise throughout: code reuse does **not** switch NX off. NX stays
enforced; the attack redirects control into functions that are already mapped
executable in the program's text, so no page is ever both written and executed.

## Concepts

The program exposes three ordinary in-binary functions and one bug:

1. **Reused gadgets:** `stage_one()` sets a shared state machine to 1 and prints
   `ONE`; `stage_two()` advances it to 2 only if it was 1 and prints `TWO`. Both
   are already executable code in the binary's text — not injected.
2. **Measurement oracle:** `oracle()` in [src/code_reuse.c](src/code_reuse.c)
   prints the marker and exits `42` only if the state machine reached 2, i.e. the
   two gadgets ran *in order*. Reaching it with status 42 proves control flow was
   redirected through a chain in the right order — a minimal return-oriented
   sequence — not a single jump and not injected code. It performs no shell, file,
   socket or external-library action.
3. **The bug:** `copy_input()` overflows a 32-byte stack buffer unless `FIXED`
   is defined, overwriting the saved return address.

## Cases

Both binaries are built non-PIE (`ET_EXEC`) with a non-executable stack and no
stack guard, from the same source. The collector reads the gadget addresses from
the local build artifacts (as Lab 05 does) and measures the saved-return offset
and the stack buffer address with GDB.

Three cases run as ordinary processes:

| Case | Payload | Observed outcome |
|---|---|---|
| `chain` | saved return → `stage_one` → `stage_two` → `oracle` | **Redirected in order:** prints `ONE`, `TWO`, the marker; exits `42` |
| `partial` | saved return → `stage_two` → `oracle` | **Wrong order:** `stage_one` never ran, so the oracle exits `43` |
| `fixed` | `code_reuse_fixed` with the chain payload | **Prevented pre-write:** the bounds check rejects the input, exits `2` |

A fourth case, the **NX control**, overwrites the saved return with the stack
buffer's own address. A stack address differs between processes under ASLR, so a
process run would point at the wrong address and its fault would prove nothing.
It is therefore measured in-process under GDB with randomization disabled: the
fault instruction pointer must equal the live stack buffer and lie in the
non-executable `[stack]` mapping, so the `SIGSEGV` is a blocked stack execution,
not a jump to unmapped memory.

The NX control and the `chain` case together are the point: the same binary,
under the same enforced NX, blocks execution of bytes on the stack but still
allows control flow to be redirected through code that was already executable.
`partial` is the control that shows the chain genuinely sequences two gadgets —
reaching the oracle is not enough; they must run in order. `fixed` shows the
root-cause repair defeats all of it.

The chain payload reuses the Lab 05 alignment structure: `offset` filler bytes,
then `(ret-gadget, target)` pairs so each reused function is entered with the
x86-64 ABI's 16-byte stack alignment.

## Build and capture

Build the two variants locally:

```bash
make -C labs/08-code-reuse-chain
```

### Automated evidence capture

Run the collector in a fresh output directory:

```bash
python3 scripts/capture-code-reuse.py host /tmp/code-reuse-host
```

The collector builds both binaries, checks each requests a non-executable stack
and (reading the symbol table) carries no stack guard, reads the gadget addresses
and a `ret` gadget from the local artifacts, and measures the saved-return offset
via GDB. It runs the three control-flow cases three times each (9 trials) with
core dumps disabled, and measures the NX control in-process under GDB, recording
the fault in `nx-fault.json`. It requires each case to be deterministic across
its repeats and writes `observations.json`, `payload.json`, `nx-fault.json`,
`finding.json`, `SHA256SUMS` and `COMPLETE`. A failed or unexpected run keeps its
partial evidence without `COMPLETE`.

Export verified portable text evidence from one or more complete captures:

```bash
python3 scripts/export-code-reuse.py /tmp/code-reuse-host --output /tmp/code-reuse.json
```

The exporter verifies the full manifest and exact artifact coverage and refuses
to overwrite an existing JSON file. The committed [portable evidence](evidence/)
records a host capture including the finding.

## Attacker assumptions and limits

1. **White-box static addresses.** The gadget and `ret` addresses are read from
   the local non-PIE build artifacts, exactly as Lab 05 reads static addresses;
   this is not an information disclosure. Against a PIE binary a leak would be
   needed first, which is the subject of Lab 06.
2. **A minimal chain, not a general ROP toolkit.** Two in-binary gadgets are
   sequenced to prove ordered reuse. The lab does not build libc gadget chains,
   does not call a real function like `system`, and reaches only a harmless
   in-binary oracle.
3. **NX remains enforced.** The result is that reuse succeeds *despite* NX, not
   that NX failed. The `shellcode` case in the same binary confirms NX still
   blocks stack execution.
4. **No real target.** Reaching the oracle shows ordered instruction-pointer
   control over existing code; it is not arbitrary code execution and not an
   attack on a real system.

## Relation to the other labs

Lab 05 redirected control flow to a single in-binary address; Lab 06 removed the
PIE precondition with a leak; Lab 07 measured that NX blocks execution of a
non-executable page. Lab 08 is the natural continuation: once stack shellcode is
blocked (Lab 07), control is redirected through *existing* executable code
instead. The repair is the same one that held throughout Labs 04–06 — a bounds
check that prevents the overwrite. Measured on x86-64; a legacy i386 comparison
is out of scope here (see Lab 03 on the legacy environment's NX limitation).
