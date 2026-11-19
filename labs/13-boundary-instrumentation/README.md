# Lab 13 - Partial Instrumentation Across a Shared-Library Boundary

Research question: When a main executable and a linked shared library are built
with different hardening settings (`both` / `main_only` / `lib_only` /
`neither`), which stack overflows are actually detected at run time — and what
does a binary-level metadata check on the main executable miss?

This is the third declared-vs-observed lab (after [Lab 11](../11-cet-shadow-stack/README.md)
on runtime activation and [Lab 12](../12-fortify-coverage/README.md) on
compile-time FORTIFY call-site coverage), targeting the **component-boundary**
axis: a protection emitted into the main executable does not cross into an
uninstrumented shared library, and vice versa.

This is a local, white-box systems-security experiment on x86-64 Linux. Run it as
an ordinary user. The outcome is an empirical observation for a specific compiler,
C library and dynamic-linking configuration.

## Matrix (2 × 2 instrumentation × 2 overflow locations)

Two shared libraries (`libboundary_on.so` with `-fstack-protector-strong`,
`libboundary_off.so` with `-fno-stack-protector`) and four executables
(`boundary_both`, `boundary_main_only`, `boundary_lib_only`, `boundary_neither`)
are built at `-O2` with `-U_FORTIFY_SOURCE` (so FORTIFY does not confound the
stack-protector signal).

Each configuration exposes the exact same 32-byte linear stack copy in both
components:

| Location | Function | Component |
|---|---|---|
| `in_main` | `copy_in_main()` | main executable (`boundary_<config>`) |
| `in_lib` | `copy_in_lib()` | shared library (`libboundary_{on,off}.so`) |

## Controls

All four pre-registered controls are measured in every configuration:

1. **Valid input (`safe`):** in-bounds copy (`n = 16 <= 32`) completes normally
   (`exit 0`) in every configuration and location.
2. **Proven bug (`neither`):** uninstrumented `attack` (`n = 80`) corrupts the
   stack frame and faults (`SIGSEGV`) without a canary abort.
3. **Full instrumentation (`both`):** both `in_main` and `in_lib` attacks abort
   with `*** stack smashing detected ***` (`SIGABRT`).
4. **Explicit source repair (`fixed`):** `n > sizeof(buf)` rejects the copy
   pre-write (`exit 2`) in **every** configuration, independent of compiler
   instrumentation.

## Baseline comparison (main-binary-only metadata oracle)

A naive binary-level hardening check run only on the main executable (analogous
to `hardening-check boundary_main`) infers `"protected"` iff `boundary_main`
imports/emits `__stack_chk_fail`. Against the 8 attack cells (4 configs × 2
locations), that rule produces **both**:

- **1 false positive** (`main_only / in_lib`): main executable has stack
  canaries, yet the overflow inside `libboundary_off.so` is unprotected
  (`SIGSEGV`, `unattributed_fault`).
- **1 false negative** (`lib_only / in_lib`): main executable has no stack
  canaries, yet `libboundary_on.so` detects the overflow inside its own frame
  (`SIGABRT`, `detected_after_operation`).

Knowing whether a call is protected therefore requires inspecting **every linked
component** *and* knowing **which component owns the overflowing stack frame**.

## Run it

```sh
make                       # builds libboundary_{on,off}.so and 4 executables
python3 ../../scripts/capture-boundary.py host /tmp/lab13-host
python3 ../../scripts/export-boundary.py /tmp/lab13-host --output evidence/<date>.json
```

The capture records the coverage matrix, the main-binary-only baseline oracle,
the four research states and the per-trial classification. `COMPLETE` is written
on capture completeness regardless of outcome, so a counter-finding is preserved
as data.
