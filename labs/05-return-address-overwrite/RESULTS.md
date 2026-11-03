# Lab 05 Results — 31 October 2026

One complete `host` capture on an Ubuntu x86-64 review machine recorded 27
trials: three runs for each of nine binary/input combinations. The operator
label is not automatic environment identification. GCC 15.2.0, glibc 2.43,
kernel 7.0.0-42-generic and ASLR setting `2` were recorded for this capture.

| Binary | Safe input | Attack input | Padding control |
|---|---|---|---|
| `overwrite_plain` | 3/3 normal return | 3/3 target reached, status 42 | 3/3 SIGSEGV, target not reached |
| `overwrite_canary` | 3/3 normal return | 3/3 SIGABRT, guard diagnostic | — |
| `overwrite_pie` | 3/3 normal return | 3/3 SIGSEGV, target not reached | — |
| `overwrite_fixed` | 3/3 normal return | 3/3 rejected, status 2 | — |

GDB measured saved-return offsets of 40 bytes for the plain, PIE and fixed
variants and 56 bytes for the canary variant. The plain target was entered with
`%rsp % 16 == 8`. The payload addresses came from the local non-PIE binary;
the experiment did not obtain them through a runtime information leak.

The canary detected a contiguous overflow after the invalid write. The fixed
variant rejected the oversized request before copying. The PIE result shows
that this fixed non-PIE address failed under ASLR in these runs; it does not
measure resistance to an address disclosure. These are observations for one
host build, not historical 32-bit measurements or a reliability estimate.

## Evidence and reproduction

[Portable text evidence](evidence/2026-10-31.json) contains all 27 observations,
stdout and stderr, signed return codes, tool versions, build output, payload
metadata, source and binary hashes, and the full capture manifest hash. It
omits binaries and full disassembly. The original complete capture is local
under the ignored `tmp/return-overwrite-host-initial/` directory.

To produce a new independent capture and export, from the repository root:

```bash
python3 scripts/capture-return-overwrite.py host /tmp/overwrite-new
python3 scripts/export-return-overwrite.py /tmp/overwrite-new \
  --output /tmp/overwrite-new.json
```

Both output paths must be new. The exporter verifies the complete capture
manifest before creating the JSON file. Hashes detect changes relative to the
manifest; they do not authenticate who ran the experiment.
