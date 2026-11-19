# Mitigation Enforcement

*(artifact: Exploit Evolution)*

[![Lab validation](https://github.com/DenizAltunkapan/mitigation-enforcement/actions/workflows/labs.yml/badge.svg)](https://github.com/DenizAltunkapan/mitigation-enforcement/actions/workflows/labs.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](README.md#run-the-checks)
<!-- On release, add the Zenodo CONCEPT DOI badge (resolves to the latest version):
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.XXXXXXX.svg)](https://doi.org/10.5281/zenodo.XXXXXXX) -->


A systems-security study comparing legacy i386 and modern x86-64 Linux
baselines, then testing exploitation primitives and mitigations in controlled
binaries. Thirteen local labs connect process layout and stack frames to
canaries, PIE/ASLR, execution permission, code reuse, RELRO, format strings,
and three declared-versus-observed enforcement studies (Intel CET shadow stack,
`_FORTIFY_SOURCE` call-site coverage, and shared-library boundaries).

**Research question:** Under which documented build, load, and runtime conditions
does declared hardening actually protect a specific operation, and which evidence
explains a gap between the declaration and observed enforcement?

## Findings

- A stack canary detects corruption after an out-of-bounds write; a bounds
  check rejects the write before it occurs. [Lab 04 results](labs/04-stack-canary/RESULTS.md)
- A same-process pointer leak enables return-address redirection under PIE+ASLR
  in the tested binary; the bounds check still blocks the path.
  [Lab 06 results](labs/06-pie-leak-bypass/RESULTS.md)
- A jump onto a non-executable stack faults, while an ordered chain of existing
  functions redirects control flow under NX. This is code reuse, not disabled
  NX. [Lab 08 results](labs/08-code-reuse-chain/RESULTS.md)
- A CET-marked binary on a shadow-stack-capable CPU still redirects while its
  process shadow stack is inactive, and faults with `SEGV_CPERR` only once
  activated; `_FORTIFY_SOURCE` checks copies per call site (L2 static, L3
  runtime, never cross-TU); and a stack protector does not cross a shared-library
  boundary. [Labs 11–13 results](docs/SYNTHESIS.md#key-results-and-evidence)

These are bounded observations from the recorded environments, not claims about
arbitrary systems. The [complete key results and evidence table](docs/SYNTHESIS.md#key-results-and-evidence)
covers all thirteen labs; the [research record](docs/RESEARCH.md) tracks failed
cases and open replications.

## Labs

| Lab | Focus |
|---|---|
| [01](labs/01-process-memory-layout/README.md) | Process memory layout on i386 and x86-64 |
| [02](labs/02-stack-frames/README.md) | Stack frames and saved return addresses |
| [03](labs/03-binary-mitigation-baseline/README.md) | ELF mitigation baseline |
| [04](labs/04-stack-canary/README.md) | Canary detection versus bounds checking |
| [05](labs/05-return-address-overwrite/README.md) | Return-address overwrite under different mitigations |
| [06](labs/06-pie-leak-bypass/README.md) | PIE/ASLR bypass using a same-process leak |
| [07](labs/07-execution-permission/README.md) | Runtime NX and W^X measurement |
| [08](labs/08-code-reuse-chain/README.md) | Code reuse under a non-executable stack |
| [09](labs/09-relro-got/README.md) | GOT overwrite under partial versus full RELRO |
| [10](labs/10-format-string/README.md) | Format-string disclosure, write primitive and FORTIFY |
| [11](labs/11-cet-shadow-stack/README.md) | CET shadow stack: requested vs. observed enforcement (anchor lab) |
| [12](labs/12-fortify-coverage/README.md) | FORTIFY coverage: when a buffer copy is actually checked, across size-knowledge variants |
| [13](labs/13-boundary-instrumentation/README.md) | Partial instrumentation across a shared-library boundary |

Labs 01–03 have a [cross-VM baseline comparison](docs/BASELINE-COMPARISON.md).
Labs 04–13 keep their results and capture evidence in the respective lab
directories. Lab 11 is the anchor for the declared-vs-observed thesis and the
first lab to record the four research states at capture time (see
[research/plan.yaml](research/plan.yaml)).

## Run the checks

On x86 Linux with Bash, Python 3.8+, GCC, GDB, Make and Binutils:

```bash
./scripts/validate.sh
```

This checks the local builds, tooling and evidence integrity without starting
VMs or downloading images. The [local review commands](docs/REVIEW-LOCALLY.md)
cover optional host captures and exports; [docs/SETUP.md](docs/SETUP.md) covers
VM setup and baseline capture.

All experiments use synthetic, local programs. They do not target real systems.
The C examples deliberately exercise undefined behavior; use disposable VMs for
manual experiments. A host run does not replace the recorded VM measurements.

## Citing

See [CITATION.cff](CITATION.cff). A versioned snapshot will be archived on Zenodo
at release; the version DOI and concept DOI badge must be added before publication.

MIT licensed; see [LICENSE](LICENSE).
