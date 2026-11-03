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
| 03: ELF mitigations | Verified VM comparison, repeated runs and ELF metadata | Runtime execution-permission experiment; no NX claim for the default legacy CPU |
| 04: stack canary | 72 recorded trials across host/Debian VM and `-O0`/`-O2`, with selected text evidence | Historical 32-bit replication after validating the recovered boot path |
| 05: return-address overwrite | [Verified host / Debian 13 VM comparison](../labs/05-return-address-overwrite/RESULTS.md) and portable JSON evidence across 4 binary variants (54 recorded trials) | Historical 32-bit i386 replication using an architecture-adapted test setup |

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

[The root README](../README.md#quickstart) provides the local entry point.
The baseline collector covers Labs 01–03; dedicated Python collectors cover
Labs 04 and 05. All build copies outside the source tree and refuse existing
output directories. Captures include their collector source.

Full capture manifests permit integrity checks. The baseline, Lab 04 and Lab 05 exporters
verify every manifest entry and exact artifact coverage before creating portable
JSON snapshots. They reject incomplete captures, modified files, extra artifacts,
duplicate entries and symlinks. They read data only and never execute captured
binaries. The baseline exporter additionally requires matching inputs when
combining captures. Selected JSON omits full binaries and disassembly, so it is suitable
for repository review but cannot replace a full capture. Hashes detect changes
relative to a manifest; they do not authenticate who ran an experiment.

VM downloads and installed packages are not pinned. Exact recorded versions
support interpretation, but do not promise bit-identical future installations.
The original Lab 04 full captures are local ignored artifacts, unavailable in a
fresh clone. Committed text snapshots preserve the observations; readers can
run fresh captures independently using the documented commands.

## Next experiments, in order

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
4. Add a narrowly scoped NX experiment that distinguishes executable-memory
   permission from memory corruption, with a stated failure criterion and repair.

## Scope

All examples are synthetic local experiments. The repository includes no
production targets, network scanning, shellcode or exploit chains. Public VM
passwords support disposable local use only. Loopback port forwarding limits
inbound exposure; user-mode NAT still permits outbound traffic. No host ASLR
settings or system-wide hardening need to be changed for validation.
