# Recovered legacy baseline — 26 October 2026

Labs 01–03 completed in the recovered Debian 7 i386 VM as `lab` (UID 1000),
with no guest network device. Five binaries ran three times each, for 15 runtime
transcripts. All four capture manifests were verified after extracting the
results from a separate data disk. The subsequent
[27 October comparison](BASELINE-COMPARISON.md) pairs this capture with Debian 13
using matching source and build inputs. The Lab 04 legacy experiment remains
outstanding.

## Environment and provenance

| Property | Recorded value |
|---|---|
| Distribution | Debian 7.11, recovered installation |
| Kernel | Linux 3.2.0-4-686-pae, Debian 3.2.78-1 |
| Architecture / word size | i686 / 32 bits |
| Compiler / target | GCC 4.7.2-5 / i486-linux-gnu |
| Binutils | 2.22 |
| libc | glibc 2.13 |
| ASLR | 2; unchanged |
| CFLAGS | `-O0 -g -Wall -Wextra -fno-omit-frame-pointer` |
| Guest CPU | QEMU Virtual CPU version 2.5+; `nx` absent from flags |
| GDB / SSH | not installed |

The [recovery guide](LEGACY-DIAGNOSIS.md) records what changed in the disk and
how normal GRUB boot was verified. Recovery used only packages from the existing
installer ISO. The source disk, ISO and flattened recovered disk hashes, package
manifest, guest CPU flags, normal boot command line, build logs, complete run
outputs, ELF metadata and source/Makefile copies are in the
[selected text evidence](evidence/legacy-baseline-2026-10-26.json).

## Lab 01: process layout

| Observation | Run 1 | Run 2 | Run 3 |
|---|---|---|---|
| `main` | `0x8048688` | `0x8048688` | `0x8048688` |
| heap allocation | `0x9f73008` | `0x9c9c008` | `0x9f72008` |
| stack local | `0xbfa52ad8` | `0xbfca4608` | `0xbfaf94e8` |
| libc executable mapping start | `0xb7578000` | `0xb765a000` | `0xb7667000` |

The non-PIE executable's text remains fixed while heap, stack and libc mappings
move across these runs. This is an observation of randomization, not a measure
of entropy or exploit reliability.

The line labelled `printf from libc` prints `0x8048460` in all three runs. That
address lies in the executable mapping, so it must not be interpreted as the
libc mapping base. The `/proc/self/maps` transcript supplies the actual libc
mapping used in the table. Symbol pointer values can reflect dynamic-linking
stubs and require interpretation alongside mappings and disassembly.

## Lab 02: stack frames

In run 1, EBP and `__builtin_frame_address(0)` both reported `0xbfbf9678`.
Argument addresses were `0xbfbf9680`, `0xbfbf9684` and `0xbfbf9688`: EBP+8,
EBP+12 and EBP+16 in this build. ESP was `0xbfbf9640`; the reported caller return
address was `0x80485d2`. These source-level observations are consistent with
stack-passed arguments in the selected i386 build. No GDB inspection of saved
return-address slots was performed; earlier debugger expectations are not new
measurements from this capture.

## Lab 03: ELF mitigation indicators

All three variants were `EXEC` files. `mitigation_default` and
`mitigation_no_pie` reported `main=0x80484db` across all three runs;
`mitigation_hardened` reported `main=0x804857d` across all three runs.
The hardened ELF imports `__stack_chk_fail`, contains `GNU_RELRO` and `BIND_NOW`,
and requests an `RW` (non-executable) `GNU_STACK`.

The guest CPU does **not** advertise `nx`. A non-executable ELF stack request
therefore must not be presented as evidence of hardware-enforced NX in this
environment. This capture includes no execution-permission experiment. Similarly,
an imported stack-guard symbol does not prove guard coverage of a specific path.

## Reproduction and limitations

Inside the recovered VM, from a copy of the repository owned by `lab`:

```bash
bash scripts/capture-baseline.sh legacy /tmp/legacy-baseline-new
```

Use a fresh output directory. For the recorded run, project files were copied
from a local read-only ISO; results were written to a separate ext filesystem.
No shared host directory or networking was used. After shutdown, `debugfs rdump`
copied the results out without mounting the disk. Its ownership-restoration
warnings were expected for a non-root host user; all manifest checks passed.

Full artifacts remain locally under
`tmp/legacy-review/extracted-results/captures/legacy-baseline/`. Verify the top
manifest and each lab manifest from their respective directories with
`sha256sum -c SHA256SUMS`. A fresh clone contains selected text evidence, not
the original full binaries, disassembly or disk images. The snapshot's `files`
keys name the corresponding original capture files; `guest_metadata` contains
the additional recovery and environment transcripts.

The recovered image is not a clean reinstall, the default QEMU CPU lacks NX,
and GDB/SSH have not been installed or validated. The original failed installer
was not reproduced. The subsequent Debian 13 capture closes the missing modern
baseline comparison, while these environment limitations still apply. Native
legacy Lab 04 collection must not silently upgrade the historical Python/toolchain.
