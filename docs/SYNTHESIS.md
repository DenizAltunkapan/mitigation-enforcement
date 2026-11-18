# Synthesis across Labs 01–10

This document ties the labs together under one question and states, for each,
what was measured, what that observation supports, and what it does not. It is a
reading guide to the recorded evidence, not a new result. Where a claim is an
interpretation rather than a measurement it is marked as such, and planned work
is kept separate from both.

## Guiding question

> Under what architectural, toolchain and runtime conditions does a memory-safety
> error produce an observable control-flow change despite stack canaries, PIE/ASLR
> and NX — and which repair actually prevents it?

Each lab answers one part of this chain:

```text
memory error -> memory effect -> primitive -> historical assumption
             -> mitigation -> remaining requirement -> root-cause repair
```

A mitigation can interrupt a particular path without repairing the error, and an
observed crash is not by itself evidence of instruction-pointer control. The labs
are built to keep those two apart.

## Key results and evidence

| Lab | Role in the chain | Measurement that carries the claim | Scope of the claim |
|---|---|---|---|
| [01 process layout](../labs/01-process-memory-layout/README.md) | Baseline: what is fixed vs. randomized | Debian 7 i386 / Debian 13 amd64 comparison with matching inputs: non-PIE text stays fixed, heap/stack/libc move | Observed in these two environments, not a randomization-entropy estimate |
| [02 stack frames](../labs/02-stack-frames/README.md) | Baseline: where the saved return address sits | VM comparison plus a modern GDB register/frame transcript | Modern transcript recorded; a legacy debugger transcript is open |
| [03 ELF mitigations](../labs/03-binary-mitigation-baseline/README.md) | Baseline: which protections a build requests | ELF metadata and repeated runs: `GNU_STACK RW`, RELRO/BIND_NOW, NX CPU flag | ELF request and CPU flag only — not runtime enforcement (deferred to Lab 07) |
| [04 stack canary](../labs/04-stack-canary/RESULTS.md) | Mitigation: detection vs. repair | 72 trials, host and VM, `-O0`/`-O2`: the guard aborts *after* the out-of-bounds write; a bounds check rejects it *before* | A contiguous linear overflow; not indexed writes or canary disclosure |
| [05 return-address overwrite](../labs/05-return-address-overwrite/RESULTS.md) | Primitive: redirect control flow, and what stops it | 54 trials across 4 variants: plain redirects to an in-binary oracle; canary aborts; PIE+ASLR faults on a static address; bounds check prevents the write | x86-64; the primitive reaches a known in-binary address, not arbitrary code |
| [06 defeating PIE with a leak](../labs/06-pie-leak-bypass/RESULTS.md) | Primitive extended: remove one precondition | 18 trials across host + Debian 13 VM (9 distinct leaked bases per environment): a same-process pointer leak rebases the target so the Lab 05 PIE+ASLR fault becomes redirection; a bounds check still prevents it | The leak is modelled as an explicit disclosure, not derived from a concrete bug |
| [07 runtime execution permission](../labs/07-execution-permission/RESULTS.md) | Mitigation boundary: measure NX vs. W^X | 18 trials across host + Debian 13 VM, 3 page protections: identical bytes fault without execute, run with it; a writable-executable mapping is allowed in both | One anonymous `mmap`/`mprotect` mapping; not loaded segments, stacks or heaps; a hardened/LSM host is untested |
| [08 code reuse under NX](../labs/08-code-reuse-chain/RESULTS.md) | Primitive extended: avoid NX instead of disabling it | 18 process trials across host + Debian 13 VM, 3 control-flow cases plus an in-process NX control: a jump onto the non-executable stack faults while an ordered chain of in-binary functions reaches the oracle; a bounds check prevents it | x86-64, white-box static addresses (no PIE leak); a minimal ordered chain, not a libc ROP toolkit; CET disabled |
| [09 GOT overwrite under RELRO](../labs/09-relro-got/RESULTS.md) | New target and its mitigation: the GOT, not the saved return | 12 trials across host + Debian 13 VM, 2 cases: overwriting puts's GOT slot redirects the call under partial RELRO but faults under full RELRO | x86-64, white-box static address (no PIE leak); one slot and one call, not a full PLT/GOT attack |
| [10 format-string vulnerability](../labs/10-format-string/RESULTS.md) | New bug class: a disclosure and write without an overflow | 24 trials across host + Debian 13 VM, 4 cases: a `%p` walk discloses a planted stack marker, `%n` changes a supplied local variable, FORTIFY aborts the same input, and a constant format prints it literally | x86-64; the marker is not a PIE-base leak and the attacker does not select an arbitrary write address |

## How the claims build on each other

- Labs 01–03 **establish the ground**: what is fixed, where the return address
  is, and which protections a modern build requests. They make no exploitation
  claim and deliberately stop at ELF requests and CPU flags.
- Lab 05 **turns the bug into a primitive** and shows, within one binary
  configuration at a time, how each mitigation changes the path: the canary turns
  redirection into a detected abort, PIE+ASLR turns it into a fault, and a bounds
  check removes the write entirely.
- Lab 06 **removes exactly one of Lab 05's preconditions** — knowledge of the text
  base — and shows the same overwrite then redirects control flow. Crucially, the
  PIE fault in Lab 05 was an information gap, not a structural guarantee; the
  bounds check, which repairs the bug, still holds.
- Lab 04 and Lab 07 **bound the mitigations themselves**: Lab 04 separates
  *detection* (canary) from *prevention* (bounds check); Lab 07 separates NX, a CPU
  feature that is enforced here, from W^X, a software policy that is not. Neither
  is an exploit; both measure where a protection does and does not act.
- Lab 08 **answers the question Lab 07 raises**: once NX blocks stack shellcode,
  how does an attack proceed? By reusing code that is already executable. An
  ordered chain of in-binary functions redirects control flow while NX stays
  enforced — confirmed because the same binary faults when the return is pointed
  at the stack buffer. The move from code injection to code reuse is the lab's
  point; the bounds check, again, is the only thing that prevents it.
- Lab 09 **changes the target, not just the mitigation**: the earlier control-flow
  primitives (Labs 05, 06 and 08) hijack the saved return address, but the GOT is a
  second control-flow pointer.
  Full RELRO maps it read-only at run time, turning the overwrite into a fault,
  while partial RELRO leaves it open. This is a different kind of defense from the
  others: it does not repair the bug but locks the writable pointer the bug would
  target.
- Lab 10 **changes the bug class**: the overflow labs (04–06, 08) all drive a
  linear buffer overflow, but a caller-controlled format string is a disclosure
  and a write with no overflow at all. A `%p` walk discloses a planted stack marker
  and a `%n` conversion changes a local variable. Here two repairs act at different
  points:
  `_FORTIFY_SOURCE=2` makes glibc reject `%n` from a writable format and abort
  before the write, stopping this one path much as RELRO locks one target, while a
  constant `"%s"` format removes the conversion entirely — the root-cause repair,
  the counterpart of the bounds check in the overflow labs.

The consistent thread: across the labs that test a repair (04–06, 08, 10) the only
change that *prevents* the effect structurally rather than merely interrupting one
path is the root-cause repair — the bounds check in the overflow labs, the constant
format in Lab 10. Labs 01–03 and 07 measure no such repair. Canary,
PIE/ASLR and NX each interrupt a path under stated conditions without repairing
the error. Full RELRO and FORTIFY sit between: they do not touch the bug, but
unlike the earlier mitigations they stop the write itself — RELRO by removing the
writable target, FORTIFY by rejecting the `%n` argument — each still bounded to one
target or one conversion.

## Failed and negative cases kept on the record

Honest negatives are part of the evidence, not omissions:

- **Legacy 32-bit replication is unresolved.** The recovered Debian 7 image boots
  and ran Labs 01–03, but a clean unattended install and its SSH transport are
  [unverified](LEGACY-DIAGNOSIS.md); the original disk lacked a GRUB installation.
  Labs 04–10 are therefore x86-64 only.
- **No NX claim for the legacy CPU.** The default legacy QEMU CPU does not
  advertise NX, so Lab 03 makes no runtime execution-prevention claim there.
- **Lab 05/06 negative controls fault as predicted.** A length-matched padding
  input and a stale (wrong-process) base both produce `SIGSEGV` without reaching
  the oracle, which is what isolates the deliberate target placement and the
  same-process leak as the enabling factors.
- **Collectors retain failed captures without `COMPLETE`.** A build or runtime
  result that does not match the stated expectation is kept for diagnosis rather
  than silently dropped.

## Limits that apply across the labs

1. **In-binary oracle or local target, not code execution.** Labs 05–09 reach or
   run an existing in-binary function, and Lab 10 changes a program-supplied local
   variable. That demonstrates instruction-pointer control to a known address,
   execution under a page permission, or a write to a supplied pointer — not
   arbitrary or attacker-supplied code execution, and not an attack on a real
   system. Where a destination is needed the program supplies it; selecting an
   arbitrary write address is out of scope.
2. **Few environments.** Labs 06–10 were recorded on two distinct software
   environments (an Ubuntu 26.04 host and a Debian 13 VM, differing in compiler,
   linker, libc and kernel, both x86-64); the Labs 01–03 baseline is one
   Debian 7 ↔ Debian 13 pairing. Agreement across two toolchains is stronger than
   one, but the VM may share the host's physical machine, cross-system differences
   (kernel, libc, CPU) are recorded rather than individually isolated, and this is
   still a small number of environments.
3. **Unpinned toolchains.** Package versions are recorded for interpretation but
   not pinned, so future installs are not guaranteed bit-identical.
4. **Checksums establish consistency, not authenticity.** Manifest hashes detect
   changes relative to a capture; they do not attest who ran it.

## Planned work (not yet measured)

Kept separate from the claims above so nothing here is read as a result:

1. Replicate Lab 07 on a hardened or LSM-restricted host to record where a
   writable-executable mapping is instead rejected (both recorded environments
   allow it).
2. A Lab 08 variant with CET/shadow-stack enabled, to record where the ordered
   chain is instead stopped by control-flow integrity.
3. Validate a clean legacy installation independently of the recovered image, as
   a precondition for any historical 32-bit replication.

(Labs 06–10 have now been replicated in the Debian 13 VM; each carries host and
modern captures with matching findings, so they are no longer host-only.)

This project is an independent educational study. It documents a way of working —
falsifiable questions, recorded evidence, explicit negatives and bounded claims —
rather than a catalogue of exploits.
