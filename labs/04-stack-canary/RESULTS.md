# Lab 04 Results — 25 October 2026

The controlled stack-canary experiment passed on the Ubuntu host and the
Debian 13 VM, at both `-O0` and `-O2`. Each capture contains three runs of each
binary/input pair: 18 observations per capture, 72 in total.

| Environment | Compiler | libc | Kernel | ASLR |
|---|---|---|---|---|
| Ubuntu 26.04.1 host, x86-64 | GCC 15.2.0 | glibc 2.43 | 7.0.0-38-generic | 2 |
| Debian 13.6 VM, x86-64 | GCC 14.2.0 | glibc 2.41 | 6.12.105+deb13-amd64 | 2 |

| Environment/build | Safe input, all variants | Unprotected overflow | Canary overflow | Fixed overflow |
|---|---|---|---|---|
| Host, `-O0` | 9/9 return normally | 3/3 SIGSEGV | 3/3 SIGABRT + guard diagnostic | 3/3 reject, status 2 |
| Host, `-O2` | 9/9 return normally | 3/3 SIGSEGV | 3/3 SIGABRT + guard diagnostic | 3/3 reject, status 2 |
| Debian VM, `-O0` | 9/9 return normally | 3/3 SIGSEGV | 3/3 SIGABRT + guard diagnostic | 3/3 reject, status 2 |
| Debian VM, `-O2` | 9/9 return normally | 3/3 SIGSEGV | 3/3 SIGABRT + guard diagnostic | 3/3 reject, status 2 |

No oversized input reached the caller's return marker in these captures. In the
canary variant the copy-completed marker was printed before the abort: detection
happened after the invalid write. In the fixed variant the request was rejected
before the copy. The unprotected crashes establish a fault for these builds,
not control over instruction execution.

Both optimization levels gave the same observed outcomes. This is replication
across two toolchains, not proof that undefined behavior always behaves this
way. The controlled pair within each capture supports the guard-detection
conclusion; comparing the host directly to Debian cannot isolate a compiler,
libc or kernel effect.

## Evidence and reproduction

[Text evidence](evidence/2026-10-25.json) records all 72 observations, including
stdout/stderr, signed return codes, signals, environment/tool versions, build
commands and logs, source/input/binary hashes, and the hash of each full capture
manifest. It is a selected text snapshot, not a replacement for the full raw
capture or a cryptographic attestation of the experiment.

Full captures remain locally under the ignored `tmp/commit-review/` directory:

```text
host-final-o0/
host-final-o2/
modern/lab04-modern-final-o0/
modern/lab04-modern-final-o2/
```

All four full manifests were verified after copying VM evidence to the host.
The captured C source SHA-256 is:

```text
626d49e0dae2ba0ff73cb43db03d5caad7fb6bd5a7aba0087875f8644a21ee43
```

Use the commands in [README](README.md) with fresh output directories. The
`-O0` runs used the default CFLAGS; the `-O2` runs used
`-O2 -g -Wall -Wextra -Werror -fno-omit-frame-pointer`. The capture labels were
`host` and `modern` respectively. Exact commands and tool versions are in the
text evidence. No ASLR setting was changed.

The full unittest suite passed on both the host and Debian VM: 11 tests per
environment, including Labs 01–03 captures, launcher arguments, both Lab 04
optimization levels, input errors, evidence integrity and failure handling.
Shell syntax and Python compilation checks also passed on the host.

## Legacy limitation

The existing Debian 7 disk was started with a temporary QEMU snapshot, but did
not reach SSH. Its display remained at `Booting from Hard Disk...`. No Lab 04
legacy measurements were obtained. The original VM disks were not modified.
A historical 32-bit comparison remains outstanding; these results do not close
that research question. The modern VM also used a temporary snapshot, and all
captured evidence was copied out before shutdown.

## Evidence tooling verification — 26 October 2026

The portable exporter was run against all four original complete captures. It
verified their full manifests and reproduced every field in the committed
`captures` array exactly, including all 72 observations. This verifies the export
path against the preserved local artifacts; it is not a new VM experiment.

From the repository root, with the original ignored captures available:

```bash
python3 scripts/export-stack-canary.py \
  tmp/commit-review/host-final-o0 \
  tmp/commit-review/host-final-o2 \
  tmp/commit-review/modern/lab04-modern-final-o0 \
  tmp/commit-review/modern/lab04-modern-final-o2 \
  --output /tmp/lab04-original-evidence.json
python3 - <<'PY'
import json
from pathlib import Path
recorded = json.loads(Path('labs/04-stack-canary/evidence/2026-10-25.json').read_text())
exported = json.loads(Path('/tmp/lab04-original-evidence.json').read_text())
if recorded['captures'] != exported['captures']:
    raise SystemExit('Evidence differs')
print('All four captures match')
PY
```

The local validation suite passed all 14 tests, including real host builds at
`-O0` and `-O2`, portable export, modified/incomplete capture rejection and
preservation of existing output. No VM was booted for this tooling review.
