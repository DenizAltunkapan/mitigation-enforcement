# Lab 11 Results - CET Shadow Stack: Requested vs. Observed Enforcement

Status: **exploratory / pilot** (host + modern-VM captures 2026-11-19; concurrent
with Phase 0 pre-registration, not a confirmatory run — see
[research/plan.yaml](../../research/plan.yaml) `scope_v1`). Evidence:
[evidence/2026-11-19.json](evidence/2026-11-19.json). 48 trials total (24 per
environment).

## Environments (two, pinned)

| Property | Host | Modern VM |
|---|---|---|
| OS | Ubuntu 26.04.1 LTS | Debian GNU/Linux 13 (trixie) |
| Kernel | 7.0.0-43-generic | 6.12.105+deb13-amd64 |
| Compiler | gcc 15.2.0 | gcc 14.2.0 |
| C library | glibc 2.43 | glibc 2.41 |
| Architecture | x86-64 | x86-64 (QEMU/KVM guest) |
| CPU shadow stack (`user_shstk`) | **supported** | **not advertised** |
| CET note emittable (`-fcf-protection=full`) | yes | **no** |
| Shadow stack active by default | no (`arch_prctl` 0x0) | n/a (no support) |
| Shadow stack active with the `SHSTK` tunable | yes (0x1) | n/a (no support) |

This lab's claim is conditional on the environment, so the result is about *where
the activation chain breaks*, not a single universal outcome. The two environments
break at **different links**, which is exactly the transferability (RQ3) point:

| Environment | first broken link | consequence |
|---|---|---|
| Host | **activated** | `cet_full` has the note and CPU support, but the shadow stack is inactive by default, so a note-only check is wrong |
| Modern VM | **emitted** | the QEMU guest's CPU model advertises no CET, so `-fcf-protection=full` emits no CET note at all; no profile can enforce |

The modern-VM capture is recorded as a complete, hypothesis-supported result: in an
environment that cannot provide a shadow stack, every attack reaches `hijack()`
exactly like the uninstrumented reference, which is what the pre-registered
expectation says for an incapable environment. It is a genuine `unsupported`-type
outcome, not a failed capture.

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

## Outcome matrix — host (24 of the 48 trials, 3 repeats per cell, deterministic)

The matrix below is the **host** environment (CET-capable). The modern VM, which
cannot emit or support CET, reaches `hijack()` in all 24 of its trials. Each tested
process reports its own shadow-stack status and, on a fault, its own `si_code`; a
block is attributed to the shadow stack only on a `SEGV_CPERR` fault.

| profile | runtime | per-process SHSTK | attack (overflow) | safe | classification (attack) |
|---|---|---|---|---|---|
| `cet_full` | default | inactive | reaches `hijack()`, exit 42 | completes | `controlled_local_effect` |
| `cet_full` | `shstk` | **active** | **SEGV_CPERR fault** (RET caught) | completes | `blocked_before_operation` |
| `cet_none` | default | inactive | reaches `hijack()`, exit 42 | completes | `controlled_local_effect` |
| `cet_none` | `shstk` | inactive (no note) | reaches `hijack()`, exit 42 | completes | `controlled_local_effect` |

## Four research states (both captures)

| State | Host | Modern VM | Meaning |
|---|---|---|---|
| capture_complete | true | true | all 24 trials + chain recorded |
| control_validity | true | true | reference reaches `hijack()`; safe controls return |
| hypothesis_supported | true | true | observed outcome matched the environment-aware expectation |
| regression_gate_passed | true | true | controls valid and hypothesis held |

`hypothesis_supported` is **not** assumed. The pre-registered expectation is
environment-aware: in a CET-capable environment `cet_full` enforces **only** under
an active shadow stack and reaches `hijack()` otherwise; in an environment that
cannot provide a shadow stack (the VM), every attack is expected to reach
`hijack()`. Both captures matched their expectation. A note-bearing,
shadow-stack-active binary that still reached `hijack()` would be a complete
capture with `hypothesis_supported=false` — the counter-finding path, verified
end-to-end in [tests/test_cet.py](../../tests/test_cet.py).

## Findings

1. **Metadata-only inference is empirically wrong on the host.** `cet_full` carries
   the full CET note and runs on a shadow-stack-capable CPU, yet with the shadow
   stack inactive **for that process** it is exploited exactly like the
   uninstrumented reference (`metadata_only_inference_would_be_wrong = true`). A
   hardening check that reads the ELF note alone would report this running process
   as protected.
2. **Enforcement is a runtime property, not a build property.** The identical
   binary is exploitable or protected depending only on per-process activation,
   and when it enforces the stop is a control-protection fault (`SEGV_CPERR`), the
   positive proof that the shadow stack — not some unrelated fault — caught the RET.
3. **Activation depends on emission, per process.** The `shstk` tunable does **not**
   activate the shadow stack for `cet_none`, because that binary carries no CET note
   (`tunable_does_not_activate_shstk_without_cet_note = true`). Conversely, emission
   without activation (`cet_full` + default) does not protect. Both links must hold,
   and both are observed in the tested process itself, not inferred.
4. **The chain breaks at a different link in a different environment (RQ3).** On the
   host it breaks at *activated*; in the Debian 13 QEMU guest it breaks earlier, at
   *emitted* — the guest's CPU model advertises no CET, so `-fcf-protection=full`
   produces no CET note at all. The same experiment yields a different, equally
   honest outcome per environment, which is the transferability result: "protected"
   cannot be read off one artifact; it depends on the whole chain in situ.

## Metadata-only oracle vs. runtime truth

The central claim — "CET note present ⇒ this operation is protected" is a false
inference — is tested directly, not merely asserted. The collector implements that
exact inference rule (the one `checksec` / `hardening-check` apply to the ELF: note
present *and* CPU support ⇒ report "protected") and compares its verdict, per
(profile, runtime), to the runtime truth (was the hijack stopped by a `SEGV_CPERR`
fault?). No external tool is invoked, so the result does not depend on a tool
version; the inference rule itself is under test. Full data:
[evidence/2026-11-19.json](evidence/2026-11-19.json) → `metadata_oracle`.

| environment | profile | runtime | metadata-only verdict | runtime truth | false positive |
|---|---|---|---|---|---|
| host | `cet_full` | default | **protected** | **not protected** | **yes** |
| host | `cet_full` | shstk | protected | protected | no |
| host | `cet_none` | default | not protected | not protected | no |
| host | `cet_none` | shstk | not protected | not protected | no |
| modern VM | `cet_full` | any | not protected (no note emitted) | not protected | no |

Host: **1 of 4 cells is a false positive** (the note-only rule calls
`cet_full`/default "protected" while the attack in fact reached `hijack()`). Modern
VM: **0** false positives — with no CET note the rule correctly says "not
protected" everywhere. The false positive is therefore not universal: it appears
exactly where a mitigation is *requested and emitted but not enforced*, which is
precisely the gap a note-only tool cannot see. This is the direct empirical rebuttal
of metadata-only inference, and the extra evidence needed to avoid it is the
per-process `arch_prctl` activation status plus the `SEGV_CPERR` faulting behaviour.

## Why the lab is -O0 (a deliberate scope, not an oversight)

The controlled overflow writes `&hijack` at a fixed offset (buffer + saved frame
pointer) onto the saved return address. That offset is specific to the `-O0`
non-PIE frame layout. At `-O2` the compiler reorders the frame and the fixed
payload no longer lands on the return address, so the overflow does not reach it
and even the uninstrumented reference returns normally — the control precondition
(reference reaches `hijack()`) fails, making an `-O2` capture uninterpretable for
*this* operation. The mitigation under test (the shadow stack) is a CPU/runtime
property that does not depend on the optimization level, so `-O0` costs no
generality here; it is the level at which the controlled overflow is well defined.
A lab whose mitigation codegen *does* vary with `-O` (Lab 04's canary) is captured
at both levels; this one is not, by design.

## Threats to validity

- **Only the host CPU is CET-capable.** The shadow-stack result (host) rests on one
  CPU's `user_shstk` support, default activation policy and glibc tunable behaviour.
  The modern VM, captured here, has no CET at all (its QEMU CPU model advertises
  none), so it cannot corroborate the *activated/effective* links — it corroborates
  only that the chain can break earlier, at *emitted*. A second physical CET host
  would be needed to replicate the shadow-stack enforcement itself; that is open.
- **IBT not exercised.** The host CPU does not advertise `ibt`, so the lab measures
  the shadow-stack half of CET only. Forward-edge (IBT) enforcement is out of scope
  here and noted, not silently omitted.
- **Controlled overflow, not a found bug.** The bug is in-binary and deterministic
  by construction, to isolate the mitigation. An external-corpus bug (QuickSafe
  subset) is deferred to v2.
