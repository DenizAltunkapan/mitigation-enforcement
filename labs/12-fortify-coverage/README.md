# Lab 12 - FORTIFY Coverage: When Is a Buffer Copy Actually Checked?

Research question: `_FORTIFY_SOURCE` asks the compiler to replace unsafe memory
calls with bounds-checked variants (`memcpy` → `__memcpy_chk`) that abort on
overflow. But the check is emitted only when the compiler can determine the
*destination's size* at the call site. Whether that holds depends on **how the
destination is known there**, not on the flag alone. This lab asks, for the same
copy in three size-knowledge variants and three FORTIFY levels: which copies are
actually checked — in the emitted code *and* at run time?

This is the second declared-vs-observed lab (after [Lab 11](../11-cet-shadow-stack/README.md)),
on a different mitigation class: a compile-time object-size check rather than a CPU
feature. It is the generalization of the real Lab 10 CI bug — the mitigation's
observable signal is build- and shape-dependent.

This is a local, white-box systems-security experiment on x86-64 Linux. Run it as
an ordinary user. The outcome is an empirical observation for a specific compiler,
C library and build configuration.

## The variants (size knowledge at the copy site)

| Variant | Destination | Can the compiler prove its size *at the memcpy*? |
|---|---|---|
| `static` | `char buf[32]` local array | yes — a compile-time constant |
| `runtime` | `malloc(cap)`, `cap` from argv | no at low levels; dynamically at L3 |
| `crosstu` | buffer whose copy runs in `sink.c` (another TU) | no — size opaque across the TU boundary |

Each variant copies `n` bytes from an opaque source (argv, so the optimizer keeps
the library call). `n > 32` overflows; `n ≤ 32` is the in-bounds baseline control.

## What is measured, separately

- **emitted** — whether `__memcpy_chk` is present in each variant's function, read
  from the binary's per-function disassembly. This is the check being *present in
  the code*, distinct from the flag being *requested*.
- **effective** — whether an actual overflow is *caught at run time* (`__memcpy_chk`
  aborts with "buffer overflow detected") or proceeds unchecked. A copy can be
  emitted-but-inert if the compiler cannot resolve the destination size, so emitted
  and effective are recorded separately.

The stack protector is **disabled** in the build so the only thing that can abort an
overflow is an effective `__memcpy_chk`; this isolates FORTIFY from the canary
(studied in [Lab 04](../04-stack-canary/README.md)). An unchecked overflow therefore
faults via the raw stack/heap, classified as `unattributed_fault` — not credited to
FORTIFY.

## Controls

- **Baseline:** the in-bounds (`safe`) copy completes normally in every cell.
- **Unguarded reference:** the `off` build (FORTIFY explicitly undefined) must never
  abort via FORTIFY — proving the aborts seen at L2/L3 are FORTIFY's, not the raw
  memory system's.

## Observed outcome (this host)

Measured coverage (see [RESULTS.md](RESULTS.md) for the full environment and the
run-time confirmation):

| variant | off | L2 | L3 |
|---|---|---|---|
| `static` | unchecked | **checked** | **checked** |
| `runtime` | unchecked | unchecked | **checked** |
| `crosstu` | unchecked | unchecked | unchecked |

Three findings, each from emitted code and confirmed by the run-time abort:

1. **Static size:** checked from L2 — the compiler proves the 32-byte object.
2. **Runtime size:** checked **only at L3** — the same `_FORTIFY_SOURCE` family
   leaves a heap copy unchecked at L2 and checks it at L3 (dynamic object size).
   This is the headline level-2-vs-3 coverage difference.
3. **Cross-TU:** **never checked, any level** — the copy runs in a translation unit
   that cannot see the destination's size, a boundary the flag cannot cross.

## Honest guard

FORTIFY needs `-O1+`; at `-O0` a requested-but-inactive check is not a failure of an
active protection. The lab therefore builds at `-O2` and records `emitted`
separately from `requested`. A hardening check that reads the flag, or even counts
`__memcpy_chk` calls, cannot tell a checked copy from an unchecked one in the same
binary — which is exactly the coverage gap this lab measures.

## Run it

```sh
make                       # builds fortify_off, fortify_l2, fortify_l3 at -O2
python3 ../../scripts/capture-fortify-coverage.py host /tmp/lab12-host
python3 ../../scripts/export-fortify-coverage.py /tmp/lab12-host --output evidence/<date>.json
```

The capture records the coverage matrix, the four research states and the per-trial
classification. `COMPLETE` is written on capture completeness regardless of which
cells were checked, so a future coverage regression is preserved as data.
