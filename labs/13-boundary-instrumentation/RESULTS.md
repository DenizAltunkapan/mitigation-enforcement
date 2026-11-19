# Lab 13 Results - Partial Instrumentation Across a Library Boundary

Status: **exploratory / pilot** (host capture 2026-11-19; concurrent with Phase 0
pre-registration, not a confirmatory run — see
[research/plan.yaml](../../research/plan.yaml) `scope_v1`). Evidence:
[evidence/2026-11-19.json](evidence/2026-11-19.json). 72 trials (4 configs × 2
locations × 3 modes × 3 repeats).

## Environment (host)

| Property | Value |
|---|---|
| OS | Ubuntu 26.04.1 LTS |
| Compiler | gcc 15.2.0 |
| C library | glibc 2.43 |
| Architecture | x86-64 |
| Optimization | `-O2` (`-U_FORTIFY_SOURCE` to isolate stack protector) |
| Linking | dynamic (`libboundary_{on,off}.so` via `RPATH=$ORIGIN`) |

A second pinned environment (Debian 13 VM) is the open transferability axis.

## Coverage matrix (emitted vs. effective, from the attack runs)

Each cell reports whether `__stack_chk_fail` is **emitted** in the target
component's function (`copy_in_main` or `copy_in_lib`) and whether an overflow
(`n = 80` into a 32-byte buffer) is **effective**ly detected at run time
(`*** stack smashing detected ***`, `SIGABRT`).

| config | `in_main` (emitted/effective) | `in_lib` (emitted/effective) |
|---|---|---|
| `neither` | no / no (`SIGSEGV`) | no / no (`SIGSEGV`) |
| `main_only` | **yes / yes** (`SIGABRT`) | no / no (`SIGSEGV`) |
| `lib_only` | no / no (`SIGSEGV`) | **yes / yes** (`SIGABRT`) |
| `both` | **yes / yes** (`SIGABRT`) | **yes / yes** (`SIGABRT`) |

Emitted and effective agree in every cell: `emitted_but_not_effective_count = 0`.

## Main-binary-only baseline oracle (8 attack cells)

A binary-level checker that inspects only the main executable (`boundary_<cfg>`)
and ignores linked shared libraries misclassifies **2 of 8 cells**:

- **False positives:** `1` (`main_only / in_lib` — executable reports stack
  canary present, library frame overflows unprotected).
- **False negatives:** `1` (`lib_only / in_lib` — executable reports no stack
  canary, library frame detects the overflow).

## Outcome classification (72 trials, deterministic)

| mode | cells | outcome |
|---|---|---|
| `safe` (in-bounds) | all 8 (config, location) cells | `controlled_local_effect` (copy completes, exit 0) |
| `fixed` (bounds check) | all 8 (config, location) cells | `blocked_before_operation` (rejected pre-write, exit 2) |
| `attack`, guarded component | `main_only/in_main`, `lib_only/in_lib`, `both/*` | `detected_after_operation` (canary abort, `SIGABRT`) |
| `attack`, unguarded component | `neither/*`, `main_only/in_lib`, `lib_only/in_main` | `unattributed_fault` (raw `SIGSEGV`, not canary) |

Classifier: `blocked_before_operation:24, controlled_local_effect:24,
detected_after_operation:12, unattributed_fault:12`.

## Four research states (this capture)

| State | Value | Meaning |
|---|---|---|
| capture_complete | true | all 72 trials + coverage + baseline oracle recorded |
| control_validity | true | `safe` completes; `neither` unguarded; `fixed` blocks all configs |
| hypothesis_supported | true | observed coverage matched the pre-registered boundary matrix |
| regression_gate_passed | true | controls valid and hypothesis held |

A counter-finding (e.g. a guarded component silently failing to abort on an
overflow) stays a complete capture with `hypothesis_supported=false`, verified
end-to-end in [tests/test_boundary.py](../../tests/test_boundary.py).

## Findings

1. **Stack-canary protection does not cross a shared-library boundary.**
   Instrumenting the main executable (`main_only`) detects overflows in `in_main`
   but leaves `in_lib` completely unprotected (`main_only_leaves_lib_unprotected
   = true`), and `lib_only` shows the exact symmetric gap
   (`lib_only_leaves_main_unprotected = true`).
2. **Executable-only hardening checks fail in both directions.** Inspecting only
   the main binary yields 1 false positive and 1 false negative across the 8
   attack cells (`main_only_oracle_false_positives = 1`,
   `main_only_oracle_false_negatives = 1`).
3. **Root-cause repair holds across every boundary.** The explicit bounds check
   (`fixed`) blocks the overflow pre-write (`exit 2`) in all four configurations
   and both components (`bounds_check_blocks_all_configs = true`), independent
   of how either binary was compiled.

## Threats to validity

- **One mitigation family.** This lab isolates `-fstack-protector-strong`.
  Sanitizers with libc interceptors (such as ASan) behave differently across
  uninstrumented callers because interceptors hook library calls rather than
  only instrumenting function prologues/epilogues.
- **One toolchain / host.** Results are specific to gcc 15.2.0 / glibc 2.43 on
  x86-64; replicating on the Debian 13 VM is the open transferability check.
- **Controlled synthetic overflow.** The overflow is deterministic and local to
  isolate boundary coverage; real multi-library dependency graphs are deferred
  to v2.
