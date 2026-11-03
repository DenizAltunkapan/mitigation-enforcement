# Lab 05 Results — 31 October – 3 November 2026

The controlled return-address overwrite experiment was executed on an Ubuntu
x86-64 review host (31 October 2026) and replicated inside a disposable
Debian 13 x86-64 virtual machine (3 November 2026). Each capture recorded 27
trials across nine binary and input combinations (three runs per combination),
yielding 54 total trials.

Both environments produced the same qualitative outcomes across all four binary
variants. The operator labels (`host`, `modern`) identify measurement runs,
not automatic hardware or distribution attestations.

## Environment and Provenance

| Property | Host review environment | Modern Debian 13 VM |
|---|---|---|
| OS / Distribution | Ubuntu 26.04.1 (x86-64) | Debian GNU/Linux 13 (trixie) |
| Kernel | Linux 7.0.0-42-generic | Linux 6.12.105+deb13-amd64 |
| Compiler | GCC 15.2.0 (Ubuntu 15.2.0-16ubuntu1) | GCC 14.2.0 (Debian 14.2.0-19) |
| Assembler / Linker | GNU Binutils 2.46 | GNU Binutils 2.44 |
| C library | glibc 2.43 | glibc 2.41 |
| Debugger | GNU GDB 17.1 | GNU GDB 16.3 |
| ASLR setting | `2` (`randomize_va_space`) | `2` (`randomize_va_space`) |
| Base image SHA-512 | — | `720d9a2d21167e8aa1bb86a8a816658c7beaeec6975c376e15a0761383a869a466cbf7fe11c287c989020070309889dd81c37cd412290531245e3562334e05f3` (`debian-13-generic-amd64.qcow2`) |
| Disk image SHA-256 | — | `fdb51649c7febdcadc85d14fe5038c008d4e5a19e3b04cdd998e0a7b89318593` (`modern.qcow2`, verified unchanged before/after via `SNAPSHOT=1`) |

The two image checksums above are recorded from the local VM setup and are not
part of the portable evidence export below; `scripts/setup-modern-vm.sh`
verifies the base image against its published `SHA512SUMS` on download. The
remaining rows are reproduced verbatim from the portable evidence.

Key package versions recorded in the VM: `gcc-14` (`14.2.0-19`), `libc6`
(`2.41-12+deb13u3`), `binutils` (`2.44-3`), `gdb` (`16.3-1`), `make` (`4.4.1-2`).

## Observed Outcomes

| Binary / Build | Safe input (`safe.input`, 16 B) | Attack input (`attack.input`, 56 B) | Padding control (`padding.input`, 56 B) |
|---|---|---|---|
| **Host**, `overwrite_plain` | 3/3 normal return, status 0 | 3/3 target reached, status 42 | 3/3 SIGSEGV (`-11`), target not reached |
| **Host**, `overwrite_canary` | 3/3 normal return, status 0 | 3/3 SIGABRT (`-6`), guard diagnostic | — |
| **Host**, `overwrite_pie` | 3/3 normal return, status 0 | 3/3 SIGSEGV (`-11`), target not reached | — |
| **Host**, `overwrite_fixed` | 3/3 normal return, status 0 | 3/3 rejected pre-write, status 2 | — |
| **VM**, `overwrite_plain` | 3/3 normal return, status 0 | 3/3 target reached, status 42 | 3/3 SIGSEGV (`-11`), target not reached |
| **VM**, `overwrite_canary` | 3/3 normal return, status 0 | 3/3 SIGABRT (`-6`), guard diagnostic | — |
| **VM**, `overwrite_pie` | 3/3 normal return, status 0 | 3/3 SIGSEGV (`-11`), target not reached | — |
| **VM**, `overwrite_fixed` | 3/3 normal return, status 0 | 3/3 rejected pre-write, status 2 | — |

## Mechanisms and Stack Layout

In both toolchains, GDB measured identical saved-return offsets and entry conditions:

- **Saved return offset:** 40 bytes for `overwrite_plain`, `overwrite_pie` and
  `overwrite_fixed`. The compiler placed the 8-byte stack canary between the buffer
  and the saved frame pointer in `overwrite_canary`, shifting the saved return
  address to offset 56.
- **Entry alignment:** `redirect_target()` was entered with `%rsp % 16 == 8`
  in both environments (`LAB05_TARGET_RSP_MOD16=8`), satisfying x86-64 ABI
  stack alignment expectations following a `call`/`ret` transfer.
- **Canary:** In `overwrite_canary`, the invalid write completed contiguously
  before epilogue checking caught the corrupted guard and invoked
  `__stack_chk_fail()` (`SIGABRT`). This confirms post-write detection.
- **PIE under ASLR:** In `overwrite_pie`, control transfer failed because the
  static address of the non-PIE target (`0x401...`) was unmapped in the randomized
  `ET_DYN` address space, resulting in a page fault (`SIGSEGV`).
- **Fixed:** In `overwrite_fixed`, the bounds check `count > sizeof(buffer)`
  intercepted the input prior to `receive_bytes()`, preventing memory corruption
  entirely.

## Methodological Boundaries and Comparison

1. **Replication across toolchains:** Consistent observations between GCC 15.2
   and GCC 14.2 demonstrate that this control-flow primitive behaves predictably
   across recent x86-64 compilers when given identical build flags.
2. **Confounding factors:** Differences in kernel version (7.0 vs. 6.12), libc
   (2.43 vs. 2.41) and hardware virtualization (bare metal vs. QEMU/KVM) exist
   simultaneously. Differences between host and VM measurements must not be
   attributed solely to Debian or to any single mitigation.
3. **Absence of ASLR bypass:** The plain exploit relies on a static target
   address from an unrandomized `ET_EXEC` binary. It does not measure resistance
   against an adversary equipped with an address-leak primitive or an entropy
   estimation.
4. **Historical limitation:** Both runs are 64-bit modern x86-64 environments.
   Legacy 32-bit replication (Debian 7 i386) remains open and requires an
   independent collector due to architectural and toolchain differences.

## Evidence and Reproduction

[Portable text evidence](evidence/2026-11-03.json) contains all 54 observations,
stdout and stderr, signed return codes, tool versions, build commands and logs,
payload metadata, source and binary hashes, and full capture manifest hashes for
both runs. Full captures remain locally under ignored directories:

```text
tmp/return-overwrite-host-initial/
tmp/return-overwrite-modern/
```

To regenerate the portable comparison evidence:

```bash
python3 scripts/export-return-overwrite.py \
  tmp/return-overwrite-host-initial \
  tmp/return-overwrite-modern \
  --output /tmp/lab05-combined.json
```

The exporter verifies the complete capture manifest and artifact coverage for
each capture before writing. Checksums establish internal consistency relative
to each manifest; they do not authenticate who executed the experiment.
