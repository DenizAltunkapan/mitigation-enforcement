# Exploit Evolution

[![Lab validation](https://github.com/DenizAltunkapan/exploit-evolution/actions/workflows/labs.yml/badge.svg)](https://github.com/DenizAltunkapan/exploit-evolution/actions/workflows/labs.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](README.md#run-the-checks)

A systems-security study comparing legacy i386 and modern x86-64 Linux
baselines, then testing exploitation primitives and mitigations in controlled
x86-64 binaries. Eight local labs connect process layout and stack frames to
canaries, PIE/ASLR, execution permission and code reuse.

**Research question:** Under which architectural, build and runtime conditions
does a memory-safety error become a control-flow primitive, and which fix
prevents the underlying error?

## Findings

- A stack canary detects corruption after an out-of-bounds write; a bounds
  check rejects the write before it occurs. [Lab 04 results](labs/04-stack-canary/RESULTS.md)
- A same-process pointer leak enables return-address redirection under PIE+ASLR
  in the tested binary; the bounds check still blocks the path.
  [Lab 06 results](labs/06-pie-leak-bypass/RESULTS.md)
- A jump onto a non-executable stack faults, while an ordered chain of existing
  functions redirects control flow under NX. This is code reuse, not disabled
  NX. [Lab 08 results](labs/08-code-reuse-chain/RESULTS.md)

These are bounded observations from the recorded environments, not claims about
arbitrary systems. The [complete key results and evidence table](docs/SYNTHESIS.md#key-results-and-evidence)
covers all eight labs; the [research record](docs/RESEARCH.md) tracks failed
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

Labs 01–03 have a [cross-VM baseline comparison](docs/BASELINE-COMPARISON.md).
Labs 04–09 keep their results and capture evidence in the respective lab
directories.

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

MIT licensed; see [LICENSE](LICENSE).
