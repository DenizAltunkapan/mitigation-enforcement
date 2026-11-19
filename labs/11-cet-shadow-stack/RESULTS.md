# Lab 11 Results - CET Shadow Stack: Requested vs. Observed Enforcement

Status: **exploratory / pilot** (host capture 2026-11-19; concurrent with Phase 0
pre-registration, not a confirmatory run — see
[research/plan.yaml](../../research/plan.yaml) `scope_v1`). Evidence:
[evidence/2026-11-19.json](evidence/2026-11-19.json).

## Environment (host)

| Property | Value |
|---|---|
| OS | Ubuntu 26.04.1 LTS |
| Kernel | 7.0.0-43-generic |
| Compiler | gcc 15.2.0 |
| C library | glibc 2.43 |
| Architecture | x86-64 |
| CPU shadow stack (`user_shstk`) | **supported** |
| CPU indirect-branch tracking (`ibt`) | not supported |
| Shadow stack active by default | **no** (`arch_prctl` status 0x0) |
| Shadow stack active with `GLIBC_TUNABLES=glibc.cpu.hwcaps=SHSTK` | yes (status 0x1) |

A second pinned environment (modern VM) is captured the same way; this lab's claim
is conditional on the environment, so the comparison is about *where the chain
breaks*, not a single universal outcome. The VM column is added when that capture
is recorded under the pinned lock.

## Activation chain (observed, per profile)

Each link is observed from a distinct source. **requested** is the build command,
not anything an ELF tool reports; **emitted** is what `readelf`/`objdump` see in
the binary; **activated** is the shadow-stack status each *tested process* reads
for itself with `arch_prctl(ARCH_SHSTK_STATUS)`, not a separate probe; **effective**
is proven by the fault's `si_code` being `SEGV_CPERR` (a control-protection fault),
not an arbitrary `SIGSEGV`.

| Link | source | `cet_full` | `cet_none` |
|---|---|---|---|
| requested (`-fcf-protection=`) | build command | full | none |
| emitted (CET note IBT+SHSTK) | `readelf -n` | **yes** | no |
| emitted (`endbr64` in own code) | `objdump -d` | 3 | 0 |
| supported (CPU `user_shstk`) | `/proc/cpuinfo` | yes | yes |
| activated — default runtime | per-process `arch_prctl` | **no** | no |
| activated — `shstk` runtime | per-process `arch_prctl` | yes | **no** |

Two independent breaks are visible. For `cet_full` the chain holds through
*supported* and breaks at *activated* in the default runtime. For `cet_none` the
`shstk` tunable does **not** activate the shadow stack at all, because the binary
carries no CET note — so *activated* depends on *emitted*, measured per process.
(The earlier draft reported `cet_none`+`shstk` as active; that was an artifact of
reading a separate probe process's status, now fixed.)

## Outcome matrix (24 trials, 3 repeats per cell, deterministic)

Each tested process reports its own shadow-stack status and, on a fault, its own
`si_code`. A block is attributed to the shadow stack only on a `SEGV_CPERR` fault.

| profile | runtime | per-process SHSTK | attack (overflow) | safe | classification (attack) |
|---|---|---|---|---|---|
| `cet_full` | default | inactive | reaches `hijack()`, exit 42 | completes | `controlled_local_effect` |
| `cet_full` | `shstk` | **active** | **SEGV_CPERR fault** (RET caught) | completes | `blocked_before_operation` |
| `cet_none` | default | inactive | reaches `hijack()`, exit 42 | completes | `controlled_local_effect` |
| `cet_none` | `shstk` | inactive (no note) | reaches `hijack()`, exit 42 | completes | `controlled_local_effect` |

## Four research states (this capture)

| State | Value | Meaning |
|---|---|---|
| capture_complete | true | all 24 trials + chain recorded |
| control_validity | true | reference reaches `hijack()`; safe controls return |
| hypothesis_supported | true | enforcement seen exactly where shadow stack is active |
| regression_gate_passed | true | controls valid and hypothesis held |

`hypothesis_supported` is **not** assumed: the pre-registered expectation is that
`cet_full` enforces **only** under an active shadow stack, and reaches `hijack()`
otherwise (like the reference). A capture where a note-bearing, shadow-stack-active
binary still reached `hijack()` would be a complete capture with
`hypothesis_supported=false` — the counter-finding path, verified in
[tests/test_cet.py](../../tests/test_cet.py).

## Findings

1. **Metadata-only inference is empirically wrong here.** `cet_full` carries the
   full CET note and runs on a shadow-stack-capable CPU, yet with the shadow stack
   inactive **for that process** it is exploited exactly like the uninstrumented
   reference (`metadata_only_inference_would_be_wrong = true`). A hardening check
   that reads the ELF note alone would report this running process as protected.
2. **Enforcement is a runtime property, not a build property.** The identical
   binary is exploitable or protected depending only on per-process activation,
   and when it enforces the stop is a control-protection fault (`SEGV_CPERR`), the
   positive proof that the shadow stack — not some unrelated fault — caught the RET.
3. **Activation depends on emission, per process.** The `shstk` tunable does **not**
   activate the shadow stack for `cet_none`, because that binary carries no CET note
   (`tunable_does_not_activate_shstk_without_cet_note = true`). Conversely, emission
   without activation (`cet_full` + default) does not protect. Both links must hold,
   and both are observed in the tested process itself, not inferred.

## What this buys over a metadata-only check

A tool such as `hardening-check` or `checksec` reports links 1-2 (requested,
emitted) from the ELF. This lab shows those links are satisfied while the
operation is *not* protected, because links 4 and 6 (activated, effective) are
not — and those are observable only at run time. The extra evidence required to
move from "CET requested" to "this RET is protected" is exactly the `arch_prctl`
activation status plus the faulting behaviour on a corrupted return address.

## Threats to validity

- **One host CPU.** `user_shstk` support, default activation policy and the glibc
  tunable behaviour are specific to this CPU, kernel and loader. The modern-VM
  capture and the pinned environment lock address transferability (RQ3); a CPU
  without `user_shstk` would record *supported = no* and a different, equally
  valid, break point in the chain.
- **IBT not exercised.** This CPU does not advertise `ibt`, so the lab measures the
  shadow-stack half of CET only. Forward-edge (IBT) enforcement is out of scope
  here and noted, not silently omitted.
- **Controlled overflow, not a found bug.** The bug is in-binary and deterministic
  by construction, to isolate the mitigation. An external-corpus bug (QuickSafe
  subset) is deferred to v2.
