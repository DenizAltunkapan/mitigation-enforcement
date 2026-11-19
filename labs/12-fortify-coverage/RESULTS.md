# Lab 12 Results - FORTIFY Coverage

Status: **exploratory / pilot** (host capture 2026-11-19; concurrent with Phase 0
pre-registration, not a confirmatory run — see
[research/plan.yaml](../../research/plan.yaml) `scope_v1`). Evidence:
[evidence/2026-11-19.json](evidence/2026-11-19.json). 54 trials (3 levels × 3
variants × 2 modes × 3 repeats).

## Environment (host)

| Property | Value |
|---|---|
| OS | Ubuntu 26.04.1 LTS |
| Compiler | gcc 15.2.0 |
| C library | glibc 2.43 |
| Architecture | x86-64 |
| Optimization | `-O2` (FORTIFY requires `-O1+`) |
| Stack protector | disabled (to isolate FORTIFY from the canary) |

This lab's result is a property of the compiler and C library, not the CPU, so a
single pinned toolchain is the meaningful unit; a second toolchain (different gcc
or glibc) is the transferability axis and is open.

## Coverage matrix (emitted vs. effective, from the attack runs)

Each cell reports whether `__memcpy_chk` is **emitted** (present in the function's
disassembly) and whether an actual overflow is **effective**ly caught at run time
("buffer overflow detected" abort). The stack protector is off, so an unchecked
overflow faults via the raw stack/heap and is *not* credited to FORTIFY.

| variant | off (emitted/effective) | L2 (emitted/effective) | L3 (emitted/effective) |
|---|---|---|---|
| `static` | no / no | **yes / yes** | **yes / yes** |
| `runtime` | no / no | no / no | **yes / yes** |
| `crosstu` | no / no | no / no | no / no |

Emitted and effective agree in every cell (no emitted-but-inert check on this
toolchain): `emitted_but_not_effective_count = 0`.

## Outcome classification (54 trials, deterministic)

| mode | cells | outcome |
|---|---|---|
| `safe` (in-bounds) | all 9 per level set | `controlled_local_effect` (copy completes) |
| `attack`, checked | L2/static, L3/static, L3/runtime | `blocked_before_operation` (FORTIFY abort) |
| `attack`, unchecked | the other 6 attack cells | `unattributed_fault` (raw overflow fault, not FORTIFY) |

Classifier: `blocked_before_operation:9, controlled_local_effect:27,
unattributed_fault:18`.

## Four research states (this capture)

| State | Value | Meaning |
|---|---|---|
| capture_complete | true | all 54 trials + coverage recorded |
| control_validity | true | in-bounds copies complete; `off` never aborts via FORTIFY |
| hypothesis_supported | true | observed coverage matched the pre-registered matrix |
| regression_gate_passed | true | controls valid and hypothesis held |

`hypothesis_supported` is **not** assumed: the pre-registered expectation is that a
copy is checked iff FORTIFY can prove the destination size there (static from L2,
runtime only at L3, crosstu never). A cell where an emitted `__memcpy_chk` failed to
abort an overflow, or where an unchecked cell was silently credited as protected,
would be a complete capture with `hypothesis_supported=false` — the counter-finding
path, verified in [tests/test_fortify_coverage.py](../../tests/test_fortify_coverage.py).

## Findings

1. **Coverage depends on size knowledge, not the flag.** The same
   `_FORTIFY_SOURCE` family checks the static copy from L2 but leaves the runtime
   (heap, opaque size) copy unchecked until L3. `runtime_coverage_differs_l2_vs_l3
   = true`: one level bump changes whether an identical operation is checked.
2. **A coverage boundary the flag cannot cross.** The cross-TU copy is never
   checked at any level (`crosstu_never_checked = true`): the `memcpy` runs in a
   translation unit that cannot see the destination's size, and no `-D_FORTIFY_SOURCE`
   level closes that gap without cross-module visibility.
3. **Emitted implies effective here.** On this toolchain every emitted
   `__memcpy_chk` actually aborted the overflow (`emitted_but_not_effective_count =
   0`), so the emitted-code signal is a faithful proxy for enforcement — but that is
   itself an observation, not an assumption; the collector records both links so a
   toolchain where they diverge (an inert chk under an unknown object size) would
   show up.

## What this buys over reading the flag

A check that reads `-D_FORTIFY_SOURCE=N`, or even counts `__memcpy_chk` calls in a
binary, cannot distinguish a checked copy from an unchecked one in the *same*
binary: this program carries both at L2 (static checked, runtime/crosstu not). The
coverage is a per-call-site property determined by what the compiler could prove
about the destination there — exactly the declared-vs-observed gap, on a
compile-time mitigation.

## Threats to validity

- **One toolchain.** The coverage matrix is specific to gcc 15.2.0 / glibc 2.43.
  A different compiler or libc version may emit checks for more or fewer cells
  (clang's `__builtin_object_size`, older glibc FORTIFY). A second toolchain is the
  open transferability axis.
- **LTO not a coverage win here.** `-flto` was tested and did not add the cross-TU
  check on this toolchain (the object-size query is resolved before cross-module
  inlining), so LTO is not part of the matrix; it is noted, not silently omitted.
- **Controlled overflow, not a found bug.** The overflow is in-binary and
  deterministic, to isolate the mitigation. An external-corpus bug is deferred to v2.
