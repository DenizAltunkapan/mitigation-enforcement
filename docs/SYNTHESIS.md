# Synthesis across Labs 01–08

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
| [06 defeating PIE with a leak](../labs/06-pie-leak-bypass/RESULTS.md) | Primitive extended: remove one precondition | 9 trials, 9 distinct leaked bases: a same-process pointer leak rebases the target so the Lab 05 PIE+ASLR fault becomes redirection; a bounds check still prevents it | The leak is modelled as an explicit disclosure, not derived from a concrete bug |
| [07 runtime execution permission](../labs/07-execution-permission/RESULTS.md) | Mitigation boundary: measure NX vs. W^X | 9 trials, 3 page protections: identical bytes fault without execute, run with it; a writable-executable mapping is allowed here | One anonymous `mmap`/`mprotect` mapping on one host; not loaded segments, stacks or heaps, nor other kernels |
| [08 code reuse under NX](../labs/08-code-reuse-chain/RESULTS.md) | Primitive extended: avoid NX instead of disabling it | 9 trials across 3 control-flow cases plus an in-process NX control: a jump onto the non-executable stack faults while an ordered chain of in-binary functions reaches the oracle; a bounds check prevents it | x86-64, white-box static addresses (no PIE leak); a minimal ordered chain, not a libc ROP toolkit; CET disabled |

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

The consistent thread: in every lab the only change that *prevents* the out-of-
bounds effect rather than merely interrupting one path is the root-cause repair
(the bounds check). Canary, PIE/ASLR and NX each interrupt a path under stated
conditions; none repairs the error.

## Failed and negative cases kept on the record

Honest negatives are part of the evidence, not omissions:

- **Legacy 32-bit replication is unresolved.** The recovered Debian 7 image boots
  and ran Labs 01–03, but a clean unattended install and its SSH transport are
  [unverified](LEGACY-DIAGNOSIS.md); the original disk lacked a GRUB installation.
  Labs 04–08 are therefore x86-64 only.
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

1. **In-binary oracle, not code execution.** Labs 05–07 reach or run an existing
   in-binary function. That demonstrates instruction-pointer control to a known
   address or execution under a page permission — not arbitrary or
   attacker-supplied code execution, and not an attack on a real system.
2. **Single host / single pairing.** Host results are one machine's; the VM
   comparison is one Debian 7 ↔ Debian 13 pairing. Cross-system differences
   (kernel, libc, CPU) are recorded but not individually isolated.
3. **Unpinned toolchains.** Package versions are recorded for interpretation but
   not pinned, so future installs are not guaranteed bit-identical.
4. **Checksums establish consistency, not authenticity.** Manifest hashes detect
   changes relative to a capture; they do not attest who ran it.

## Planned work (not yet measured)

Kept separate from the claims above so nothing here is read as a result:

1. Replicate Labs 06, 07 and 08 in the Debian 13 VM, so the PIE-leak, W^X and
   code-reuse findings are not host-only.
2. Replicate Lab 07 on a hardened or LSM-restricted host to record where a
   writable-executable mapping is instead rejected.
3. A Lab 08 variant with CET/shadow-stack enabled, to record where the ordered
   chain is instead stopped by control-flow integrity.
4. Validate a clean legacy installation independently of the recovered image, as
   a precondition for any historical 32-bit replication.

This project is an independent educational study. It documents a way of working —
falsifiable questions, recorded evidence, explicit negatives and bounded claims —
rather than a catalogue of exploits.
