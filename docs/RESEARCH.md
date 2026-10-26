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
| 01: process layout | Verified recovered Debian 7 runtime capture; earlier modern samples and image metadata | Matched modern recapture |
| 02: stack frames | Verified recovered Debian 7 runtime capture; earlier modern debugger observations | Matched modern recapture and preserved debugger transcripts |
| 03: ELF mitigations | Verified recovered Debian 7 ELF/runtime capture; earlier Ubuntu host samples | Matched modern recapture; no runtime NX claim for the default legacy CPU |
| 04: stack canary | 72 recorded trials across host/Debian VM and `-O0`/`-O2`, with selected text evidence | Historical 32-bit replication after validating the recovered boot path |

The earlier Lab 01–03 README tables are exploratory notes. Some historical values were
read from a LiveCD filesystem or package manifest rather than a running program.
They must not be treated as matched historical-versus-modern measurements. The
[26 October legacy results](BASELINE-RESULTS.md) now provide runtime evidence
from a recovered installation, with source and build provenance. Its default
QEMU CPU does not advertise NX; ELF stack flags alone cannot establish execution
prevention in that environment.
Lab 04's [results](../labs/04-stack-canary/RESULTS.md) distinguish host and VM
observations and explicitly record the failed legacy attempt.

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

[The root README](../README.md#review-locally) provides the local entry point.
The baseline collector covers Labs 01–03; the dedicated Python collector covers
Lab 04. Both build copies outside the source tree and refuse existing output
directories. Captures include their collector source.

Full capture manifests permit integrity checks. The Lab 04 exporter verifies
every manifest entry and exact artifact coverage before creating a portable JSON
snapshot. It rejects incomplete captures, modified files, extra artifacts,
duplicate entries and symlinks. It reads data only and never executes captured
binaries. Selected JSON omits full binaries and disassembly, so it is suitable
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
2. Capture Labs 01–03 on Debian 13 amd64 using the same source and protocol as
   the preserved Debian 7 capture. Replace preliminary comparison tables only
   when the matched modern transcripts are saved.
3. Replicate Lab 04 with the historical toolchain. Debian 7's stock Python cannot
   run the Python 3.8+ collector: document external collection rather than silently
   replacing the guest runtime or mislabelling host output.
4. Pin VM image identifiers/checksums and record package manifests, then perform
   a clean-machine reproduction before extending the number of labs.
5. Add a narrowly scoped NX experiment that distinguishes executable-memory
   permission from memory corruption, with a stated failure criterion and repair.

## Scope

All examples are synthetic local experiments. The repository includes no
production targets, network scanning, shellcode or exploit chains. Public VM
passwords support disposable local use only. Loopback port forwarding limits
inbound exposure; user-mode NAT still permits outbound traffic. No host ASLR
settings or system-wide hardening need to be changed for validation.
