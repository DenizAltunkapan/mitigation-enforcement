# Exploit Evolution

[![Lab validation](https://github.com/DenizAltunkapan/exploit-evolution/actions/workflows/labs.yml/badge.svg)](https://github.com/DenizAltunkapan/exploit-evolution/actions/workflows/labs.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](README.md#quickstart)

A systems-security lab comparing classical exploitation primitives on legacy
32-bit Linux and modern x86-64 Linux.

## Research question

How do architecture, toolchain defaults and runtime mitigations change the path
from a memory-safety bug to an exploitation primitive?

The point is not to collect exploits. The labs examine historical assumptions
and modern mitigations. The memory-corruption experiments distinguish an
interrupted exploit path from a repair of the underlying bug. All examples are
synthetic and local. Lab 05 uses an in-binary oracle to measure control-flow
redirection; no lab targets a real system. This is an independent educational
research project in progress.

## Key results

| Finding | Evidence |
|---|---|
| A single same-process text-pointer leak makes a saved-return overwrite redirect control flow under PIE+ASLR settings comparable to Lab 05's faulting case; a bounds check still prevents it. | [Lab 06](labs/06-pie-leak-bypass/RESULTS.md) — 3 cases, 9 trials on x86-64 host, 9 distinct leaked bases |
| The same linear stack overflow is detected after the write by a stack canary, prevented before the write by a bounds check, and faults under PIE+ASLR when a static address is reused. | [Lab 05](labs/05-return-address-overwrite/RESULTS.md) — 4 variants, 54 trials on x86-64 host and Debian 13 VM |
| A stack-canary guard detects corruption but does not prevent the out-of-bounds write; an explicit bounds check does. Holds at `-O0` and `-O2`. | [Lab 04](labs/04-stack-canary/RESULTS.md) — 72 trials, host and Debian VM |
| Non-PIE text stays at a fixed address while modern default-PIE text moves; heap, stack and libc mappings move in both environments. | [Labs 01–03 baseline](docs/BASELINE-COMPARISON.md) — Debian 7 i386 / Debian 13 amd64, matching inputs, verified manifests |

A mitigation can interrupt a path without repairing the bug, and an observed
crash does not establish instruction-pointer control. The legacy i386
replication of Labs 04–05 remains open; see
[methodology, evidence status and next experiments](docs/RESEARCH.md) for the
limits of the results and the remaining work.

## Labs

Labs 01–03 establish the baseline; Labs 04–06 introduce controlled
memory-corruption experiments.

| Lab | Topic | Target | Recorded evidence |
|---|---|---|---|
| [01](labs/01-process-memory-layout/README.md) | Process memory layout | i386 / x86-64 | Verified Debian VM comparison |
| [02](labs/02-stack-frames/README.md) | Stack frames | i386 / x86-64 | VM comparison and modern GDB transcript |
| [03](labs/03-binary-mitigation-baseline/README.md) | ELF mitigations | i386 / x86-64 | Verified VM metadata and runs |
| [04](labs/04-stack-canary/README.md) | Stack canary | x86-64 host / VM | [72 trials](labs/04-stack-canary/RESULTS.md), `-O0` / `-O2` |
| [05](labs/05-return-address-overwrite/README.md) | Return-address overwrite | x86-64 host / VM | [4 variants, 54 trials](labs/05-return-address-overwrite/RESULTS.md) |
| [06](labs/06-pie-leak-bypass/README.md) | Defeating PIE with a leak | x86-64 host | [3 cases, 9 trials](labs/06-pie-leak-bypass/RESULTS.md) |

Labs 01–03 share a cross-lab [baseline report](docs/BASELINE-RESULTS.md) and
[comparison evidence](docs/evidence/). The independent Lab 04, 05 and 06 captures
have `RESULTS.md` and `evidence/` within their own lab directories.

## Quickstart

On x86 Linux, install Bash, Python 3.8+, GCC, GDB, GNU Make, Binutils,
coreutils, QEMU utilities (`qemu-img`) and e2fsprogs (`mke2fs`, `e2fsck`,
`debugfs`). From the repository root:

```bash
./scripts/validate.sh
```

This verifies builds, tooling and evidence integrity locally. No VM startup,
ISO download, root access or network access is needed. The C examples
intentionally include undefined behavior; use a disposable VM for manual
experiments. A host run confirms the local tooling and does not substitute for
the recorded VM measurements.

## Review locally

With the Quickstart prerequisites installed, run these optional host captures
from the repository root, using fresh output paths:

```bash
python3 scripts/capture-stack-canary.py host /tmp/canary-review
python3 scripts/export-stack-canary.py /tmp/canary-review \
  --output /tmp/canary-review.json
python3 scripts/capture-return-overwrite.py host /tmp/overwrite-review
python3 scripts/export-return-overwrite.py /tmp/overwrite-review \
  --output /tmp/overwrite-review.json
python3 scripts/capture-pie-leak.py host /tmp/pie-leak-review
python3 scripts/export-pie-leak.py /tmp/pie-leak-review \
  --output /tmp/pie-leak-review.json
# Optional Labs 01–03 host capture and verified text export:
bash scripts/capture-baseline.sh host /tmp/baseline-review
python3 scripts/export-baseline.py /tmp/baseline-review \
  --output /tmp/baseline-review.json
```

A host label is a local smoke test; it does not replace VM results.

## VM setup and baseline capture

The Debian 13 (modern x86-64) and Debian 7 (legacy i386) VM setup, disposable
snapshot sessions, and the baseline capture and export workflow are documented
in [docs/SETUP.md](docs/SETUP.md).

## Non-goals

- Not a weaponized exploit collection.
- Not a chapter-by-chapter reproduction of any book.
- No copyrighted source code, disk images or third-party binaries are committed.
- No scanning or attacking real systems.

## License

MIT. See [LICENSE](LICENSE).
