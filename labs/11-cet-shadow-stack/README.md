# Lab 11 - CET Shadow Stack: Requested vs. Observed Enforcement

Research question: Labs 05-10 each measure whether *one* mitigation, once built
in, prevents a specific operation. This lab asks the question the whole project
is named for directly: **for a given operation, which link of the activation
chain is actually satisfied?** A build flag asking for a mitigation, and an ELF
marker recording that request, are *not* the same as the mitigation enforcing at
run time. Intel CET's shadow stack makes the gap measurable on commodity
hardware, because its emission (a build fact) and its activation (a runtime fact)
can hold or fail independently.

This is a local, white-box systems-security experiment on x86-64 Linux. Run it as
an ordinary user on a review host or in a disposable VM. The outcome is an
empirical observation for a specific compiler, linker, C library, kernel and CPU.

This lab is the anchor for the declared-vs-observed thesis. It is also the first
lab that records the four research states at capture time (see
[research/plan.yaml](../../research/plan.yaml)), so a mitigation that silently
fails to enforce is a *complete* capture with `hypothesis_supported=false`, not a
discarded one.

## The activation chain

A claim that "this operation is protected by the shadow stack" needs every link:

| Link | What it means | How this lab observes it |
|---|---|---|
| **requested** | the build flag asks for CET | `-fcf-protection=full` on `cet_full` |
| **emitted** | the instrumentation is in the binary | CET note (IBT, SHSTK) + `endbr64`, via `readelf -n` / `objdump` |
| **supported** | the CPU provides the feature | `user_shstk` in `/proc/cpuinfo` flags |
| **activated** | the loader/kernel turned it on | `arch_prctl(ARCH_SHSTK_STATUS)` read *by the tested process itself* at run time |
| **covered** | the operation is in a protected region | the tested RET is an ordinary function return |
| **effective** | the guarantee holds for this case | the corrupted return faults with `si_code == SEGV_CPERR` (a control-protection fault), not an arbitrary `SIGSEGV` |

The point is that the links are independent. A binary can satisfy *requested*,
*emitted* and *supported* and still fail at *activated*, in which case it is not
effective — while its ELF metadata is unchanged.

## The operation under test

The program exposes one bug and one target, in the controlled-overflow style of
Labs 05/08:

1. **The target:** an in-binary `hijack()` that prints a marker and exits `42`.
   It performs no shell, file, socket or external action; reaching it shows a
   control-flow redirect landed there.
2. **The bug:** [src/shadow_stack.c](src/shadow_stack.c) builds a fixed in-binary
   payload (filler, then `&hijack` at the saved-return-address offset) and copies
   it into a short buffer in `victim()`, overwriting the saved return address. No
   external input, no information disclosure; `&hijack` is the program's own
   symbol. A shadow stack must fault on the `RET` because the return address no
   longer matches the shadow copy.
3. **The mitigation:** the CET shadow stack. `cet_full` is built with
   `-fcf-protection=full` (CET note + `endbr64`); `cet_none` with
   `-fcf-protection=none` as the uninstrumented reference. Everything else is
   identical, so the only control-flow guarantee under test is the shadow stack.

Each binary is run under two runtime states: `default` (the shadow stack as the
loader leaves it) and `shstk` (`GLIBC_TUNABLES=glibc.cpu.hwcaps=SHSTK`, requesting
activation). Modes: `attack` (full overwrite) and `safe` (non-overflowing copy, a
baseline control that returns normally). Three repeats per cell, 24 trials.

## Controls

- **Baseline:** `safe` mode returns through an unmodified stack (`main completed`).
- **Proven bug:** `cet_none` under `attack` must reach `hijack()` on every runtime
  — this proves the overflow and the stack layout are real, independent of CET.
- **Uninstrumented reference:** `cet_none` is the same program without the CET
  request, so any difference from `cet_full` is attributable to CET alone.

## Observed outcome (this host)

Measured on x86-64 with `user_shstk` supported but **not active by default**
(see [RESULTS.md](RESULTS.md) for the full environment; this is a single-host
pilot, modern-VM replication is still open). The same `cet_full` binary:

| profile | runtime | attack (overflow) | classification |
|---|---|---|---|
| `cet_full` (note present) | default (shstk inactive) | reaches `hijack()`, exit 42 | `controlled_local_effect` |
| `cet_full` (note present) | shstk active | **SEGV_CPERR fault** (RET caught) | `blocked_before_operation` |
| `cet_none` (no note) | default | reaches `hijack()`, exit 42 | `controlled_local_effect` |
| `cet_none` (no note) | shstk requested | shadow stack stays inactive (no note), reaches `hijack()`, exit 42 | `controlled_local_effect` |

Three empirical statements follow, all from measured data:

1. With the shadow stack inactive **for that process**, the CET-note binary is
   **behaviorally identical to the uninstrumented reference** — its metadata claims
   protection that the running process does not have.
2. The *same binary* flips from exploitable to protected based only on per-process
   activation; the build flag and ELF note are necessary but not sufficient. When it
   enforces, the stop is a `SEGV_CPERR` control-protection fault, the positive proof
   that the shadow stack caught the RET.
3. Requesting activation (`GLIBC_TUNABLES=…SHSTK`) does **not** activate the shadow
   stack for `cet_none`: a binary without the CET note cannot have it enabled, so
   *activated* depends on *emitted*. Both links are read from the tested process
   itself, not inferred.

## Honest guard

A tool that correctly reports the CET note is **not wrong**. What is wrong is the
*inference* "CET note present ⇒ this operation is shadow-stack protected." This
lab tests that inference, not the tool. The `finding.json` field
`metadata_only_inference_would_be_wrong` is true exactly when a note-bearing
binary still reaches `hijack()` in a declared-but-unenforced run.

## Run it

```sh
make                       # builds cet_full and cet_none
# measured capture (writes evidence under a chosen output dir):
python3 ../../scripts/capture-cet.py host /tmp/lab11-host
python3 ../../scripts/export-cet.py /tmp/lab11-host --output evidence/<date>.json
```

The capture records the activation chain, the four research states and the
per-trial classification. `COMPLETE` is written whenever the capture is complete,
regardless of whether the shadow stack enforced — so a future regression (a
toolchain where activation silently stops working) is preserved as data.
