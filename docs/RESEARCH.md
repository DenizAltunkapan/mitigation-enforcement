# Research method and evidence status

## Question

How do modern compiler, architecture, operating-system and runtime mitigations
change the assumptions required to turn a memory-corruption bug into a useful
exploitation primitive?

Each experiment follows the same reasoning chain:

```text
programming error -> memory effect -> primitive -> historical assumption
                  -> mitigation -> remaining requirement -> root-cause repair
```

A mitigation can interrupt a particular path without repairing the programming
error. An observed crash does not establish instruction-pointer control or
arbitrary code execution.

## Evidence status

| Lab | Available evidence | What remains open |
|---|---|---|
| 01: process layout | Verified Debian 7 / Debian 13 comparison with matching source and build inputs | More samples if estimating randomization rather than observing it |
| 02: stack frames | Verified VM comparison plus modern GDB register/frame transcript | Legacy debugger transcript |
| 03: ELF mitigations | Verified VM comparison, repeated runs and ELF metadata | Runtime execution-permission enforcement is now measured in Lab 07; no NX claim for the default legacy CPU |
| 04: stack canary | 72 recorded trials across host/Debian VM and `-O0`/`-O2`, with selected text evidence | Historical 32-bit replication after validating the recovered boot path |
| 05: return-address overwrite | [Verified host / Debian 13 VM comparison](../labs/05-return-address-overwrite/RESULTS.md) and portable JSON evidence across 4 binary variants (54 recorded trials) | Historical 32-bit i386 replication using an architecture-adapted test setup |
| 06: defeating PIE with a leak | [Host + Debian 13 VM capture](../labs/06-pie-leak-bypass/RESULTS.md) with portable JSON evidence across 3 cases in each environment (18 trials, 9 distinct leaked bases per environment) | The leak is assumed, not derived from a specific bug class; historical 32-bit i386 replication |
| 07: runtime execution permission | [Host + Debian 13 VM capture](../labs/07-execution-permission/RESULTS.md) with portable JSON evidence across 3 page-protection modes in each environment (18 trials), confirming NX enforcement and an unenforced W^X policy in both | Hosts with an LSM or hardened kernel may reject the writable-executable mapping |
| 08: code reuse under NX | [Host + Debian 13 VM capture](../labs/08-code-reuse-chain/RESULTS.md) with portable JSON evidence across 3 control-flow cases in each environment (18 process trials) and an in-process NX control: a jump onto the non-executable stack faults in the [stack] mapping while an ordered chain of in-binary functions redirects control flow; a bounds check prevents it | CET/shadow-stack and libc-gadget variants are out of scope; white-box static addresses (no PIE leak) |
| 09: GOT overwrite under RELRO | [Host + Debian 13 VM capture](../labs/09-relro-got/RESULTS.md) with portable JSON evidence across 2 cases in each environment (12 trials): overwriting puts's GOT slot redirects the call under partial RELRO (status 42) but faults under full RELRO (SIGSEGV) | One slot and one call, not a full PLT/GOT attack; white-box static address (no PIE leak) |
| 10: format-string vulnerability | [Host + Debian 13 VM capture](../labs/10-format-string/RESULTS.md) with portable JSON evidence across 4 cases in each environment (24 trials): a `%p` walk discloses a planted stack marker, `%n` changes a program-supplied local variable (status 42), FORTIFY aborts the same input (SIGABRT), and a constant format prints it literally | The disclosure is not the PIE-base leak of Lab 06, and the attacker does not select an arbitrary write address |
| 11: CET shadow stack | [Host + Debian 13 VM capture](../labs/11-cet-shadow-stack/RESULTS.md) with portable JSON evidence across 2 profiles and 2 runtime states in each environment (48 trials): a CET-marked binary redirects while its shadow stack is inactive and faults with `SEGV_CPERR` once active on the host | IBT (indirect branch tracking) half of CET is out of scope; modern VM lacks CET support and does not independently replicate active shadow-stack enforcement; exploratory pilot |
| 12: FORTIFY coverage | [Host capture](../labs/12-fortify-coverage/RESULTS.md) with portable JSON evidence across 3 size-knowledge variants and 3 levels (54 trials): static copies checked from `=2`, runtime from `=3`, and cross-TU at none | Single modern toolchain; VM replication; exploratory pilot |
| 13: boundary instrumentation | [Host capture](../labs/13-boundary-instrumentation/RESULTS.md) with portable JSON evidence across 4 instrumentation configs and 2 components (72 trials): canary emitted into one component does not protect the other | Single modern toolchain; VM replication; exploratory pilot |

The Lab 01–03 guides now use the [verified VM comparison](BASELINE-COMPARISON.md).
It pairs the recovered Debian 7 capture from 26 October with the Debian 13
capture from 27 October. All C sources, Makefiles, collector and build-variable
values match; architecture, compiler, libc, kernel and CPU configuration differ.
The default legacy QEMU CPU does not advertise NX; ELF stack flags alone cannot
establish execution prevention in that environment.
Lab 04's [results](../labs/04-stack-canary/RESULTS.md) distinguish host and VM
observations and explicitly record the failed legacy attempt.
Lab 05's [results](../labs/05-return-address-overwrite/RESULTS.md) compare host
and Debian 13 VM observations under identical build flags; historical 32-bit
replication remains open.
Lab 06's [results](../labs/06-pie-leak-bypass/RESULTS.md) use a separate program
under PIE build settings comparable to Lab 05's `overwrite_pie`, not a rerun of
Lab 05's binary: a same-process pointer leak makes the overwrite redirect
control flow where ASLR alone made it crash, while an equivalent bounds check
still prevents it. The contrast was recorded in both the host and the Debian 13
VM. The leak is modelled as an explicit disclosure; deriving it from a concrete
bug class remains open.

Lab 07's [results](../labs/07-execution-permission/RESULTS.md) supply the runtime
execution-permission test Lab 03 left open. Copying one in-binary oracle into an
anonymous mapping and calling it under three page protections shows that, for
this mapping, the page's execute permission decides whether the identical bytes
run (fault under `rw`, success under `rx`), and that both recorded environments
enforce NX but not W^X: each allowed a writable-executable mapping. The result is
scoped to this anonymous-mapping probe, not to loaded segments, stacks or heaps. NX (a CPU feature) and W^X (a software policy) are
recorded as distinct claims; a hardened or LSM-restricted host may instead reject
the writable-executable mapping — that case is not yet recorded.

Lab 08's [results](../labs/08-code-reuse-chain/RESULTS.md) continue from Lab 07:
once stack shellcode is blocked, control is redirected through code that is
already executable. In one non-PIE binary under enforced NX, a stack overflow
chains two in-binary functions in order into a harmless oracle (status 42), while
the same binary faults when the saved return is pointed at the non-executable
stack buffer (SIGSEGV). The language is kept exact — NX stays enforced; the chain
avoids it by reusing executable code rather than injecting it. The gadget
addresses are read from the local build artifacts (no PIE leak, unlike Lab 06),
and the bounds-check build prevents the overwrite, the same repair that held in
Labs 04–06.

Lab 09's [results](../labs/09-relro-got/RESULTS.md) move the target off the stack.
The earlier control-flow primitives (Labs 05, 06 and 08) all hijack the saved
return address; the GOT is a second control-flow pointer the loader writes. Writing the address of an in-binary oracle
into `puts`'s GOT slot redirects the call under partial RELRO (`-z lazy`, status 42),
while the identical write faults under full RELRO (`-z now`, SIGSEGV) because the
loader has mapped the GOT read-only at startup. The two builds differ only in that
link flag; the static slot address is read from each build's own artifacts (no PIE
leak). This measures a mitigation of a different kind: full RELRO does not repair
the bug, it removes the writable target the bug would use.

Lab 10's [results](../labs/10-format-string/RESULTS.md) change the bug class. A
format string under caller control is both a read and a write primitive without a
linear buffer overflow: a `%p` walk discloses a planted stack marker (not the
PIE-base pointer leak of Lab 06), and a `%n` conversion with a program-supplied
pointer changes a local test variable (status 42). `_FORTIFY_SOURCE=2` makes glibc
reject `%n` from a writable format and abort (SIGABRT) before the write lands,
while a constant `"%s"` format removes the conversion entirely and prints the input
literally. FORTIFY stops this one write path much as RELRO locks one target; the
constant format is the root-cause repair, the counterpart of the bounds check in
the overflow labs.

Lab 11's [results](../labs/11-cet-shadow-stack/RESULTS.md) serve as the anchor for
declared-versus-observed enforcement. Testing an in-binary overwrite of the saved
return address against an Intel CET shadow stack reveals that a binary compiled
with `-fcf-protection=full` (emitting the GNU property note) on a shadow-stack-capable
CPU still redirects control flow while its shadow stack is inactive at run time.
It faults with `SEGV_CPERR` only once active (via GLIBC tunables). The activation chain
breaks at different links across environments: missing runtime activation on the host,
and missing hardware/compiler emission in the VM.

Lab 12's [results](../labs/12-fortify-coverage/RESULTS.md) measure `_FORTIFY_SOURCE`
coverage across size-knowledge variants for the evaluated toolchain (GCC 15.2.0 and
glibc 2.43 at `-O2`). Under this evaluation, emitted code (`__memcpy_chk`) and runtime
effectiveness agree per call site: a static buffer copy is checked from `=2`, a heap
allocation with runtime size only at `=3`, and a cross-translation-unit copy at neither
level. Neither the compiler flag nor counting `__memcpy_chk` symbols proves that a
particular copy operation is protected across arbitrary toolchains or optimization levels.

Lab 13's [results](../labs/13-boundary-instrumentation/RESULTS.md) measure stack-protector
enforcement across a shared-library boundary. A canary emitted into the main executable
does not protect an uninstrumented linked library, and vice versa. An executable-only
inspection yields both a false positive (main has canaries, library overflow is
unprotected) and a false negative (main has none, library detects its own overflow).

## Experiment protocol

1. State a falsifiable question, expected observation and rejection criterion.
2. Use a local synthetic program. Record the source and Makefile hashes.
3. Hold compiler, optimization, input, linker flags and environment constant
   within each mitigation comparison. Change one protection at a time.
4. Record OS, kernel, architecture, compiler target/version, linker, libc,
   ASLR setting, commands and actual build output. Environment labels are
   supplied by the operator; `modern` is not automatic VM identification.
5. Preserve inputs, stdout/stderr, signed process return codes, ELF metadata
   and disassembly. Repeat trials; retain failed captures without `COMPLETE`.
6. Separate observations from interpretations. Identify confounders and test
   the root-cause repair using the same input path.

Three identical trials establish repeatability for those builds. They do not
estimate exploit reliability, ASLR entropy or a population-level failure rate.
Cross-system differences include ABI, compiler, libc and kernel, and cannot
isolate the effect of any one of those variables.

## Reproduction and evidence integrity

[The root README](../README.md#run-the-checks) provides the local entry point.
The baseline collector covers Labs 01–03; dedicated Python collectors cover
Labs 04–13, one per lab. All build copies outside the source tree and refuse existing
output directories. Captures include their collector source. Lab 11 additionally
records the activation chain and the four research states at capture time, and
writes its `COMPLETE` marker on capture completeness rather than on the expected
outcome, so a counter-finding stays a complete capture.

Full capture manifests permit integrity checks. The baseline and the Labs 04–13 exporters
verify every manifest entry and exact artifact coverage before creating portable
JSON snapshots. They reject incomplete captures, modified files, extra artifacts,
duplicate entries and symlinks. They read data only and never execute captured
binaries. The baseline exporter additionally requires matching inputs when
combining captures. Selected JSON omits full binaries and disassembly, so it is suitable
for repository review but cannot replace a full capture. Hashes detect changes
relative to a manifest; they do not authenticate who ran an experiment.

Two automated checks keep the committed evidence honest against later edits.
`tests/test_results_consistency.py` reads only the committed JSON, Markdown and
source: it ties every version, trial count, operating system and saved-return
offset stated in a RESULTS.md back to the recorded evidence, and every recorded
collector and source hash back to the file on disk. `scripts/verify-reproducible.py`,
run in CI, goes further for the host captures: it re-runs each committed collector
and confirms the fresh outcomes — every observation's return code, signal and
outcome flags, and the finding — match the committed evidence, ignoring only the
inherently per-run fields (timestamps, raw output and ASLR-randomized addresses).
So a collector cannot drift from the evidence it is supposed to produce.

VM downloads and installed packages are not pinned. Exact recorded versions
support interpretation, but do not promise bit-identical future installations.
The original Lab 04 full captures are local ignored artifacts, unavailable in a
fresh clone. Committed text snapshots preserve the observations; readers can
run fresh captures independently using the documented commands.

## Next experiments, in order

Labs 06–10 have now been replicated in the Debian 13 VM; each carries host and
modern captures with matching findings. Lab 11 has captures in both environments
supporting the environment-dependent hypothesis, but because the modern VM lacks CET
CPU and compiler support, it does not independently replicate active shadow-stack
enforcement. Labs 12–13 carry exploratory host captures.
The remaining open work is:

1. Validate a clean legacy installation independently of the recovered image. The completed
   [offline diagnosis](LEGACY-DIAGNOSIS.md) found a filesystem that passed the
   read-only check, with kernel/initramfs present but no GRUB installation.
   The recovered overlay passed normal GRUB boot, serial login and Labs 01–03;
   its flattened local copy preserves those disk contents. A clean unattended
   install and SSH transport remain unverified.
2. Replicate Lab 04 with the historical toolchain. Debian 7's stock Python cannot
   run the Python 3.8+ collector: document external collection rather than silently
   replacing the guest runtime or mislabelling host output.
3. Pin VM image identifiers/checksums and record package manifests, then perform
   a clean-machine reproduction before extending the number of labs.
4. Lab 07: replicate on a hardened or LSM-restricted host to record where a
   writable-executable mapping is instead rejected (the two recorded environments
   both allow it).
5. Replicate Labs 12 and 13 inside the pinned modern VM.

## Scope

All examples are synthetic local experiments. The repository includes no
production targets, network scanning, shellcode or exploit chains. Public VM
passwords support disposable local use only. Loopback port forwarding limits
inbound exposure; user-mode NAT still permits outbound traffic. No host ASLR
settings or system-wide hardening need to be changed for validation.
