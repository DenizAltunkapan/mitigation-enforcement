# Lab 05 - Return-Address Overwrite Under Mitigations

Research question: under what architectural and build preconditions does a
linear stack buffer overflow redirect control flow by overwriting the saved
return address, and what exact failure signature is observed when stack
protection, PIE or an explicit bounds check is introduced?

This is a local, white-box systems-security experiment on x86-64 Linux. Run it
as an ordinary user inside a disposable VM or on a local review host. The
overflow has undefined behavior in C; its outcome is an empirical observation
for a specific compiler, ABI and binary configuration.

## Underlying Mechanism and Local Control-Flow Oracle

The experiment separates three concepts that are often conflated in informal
write-ups:

1. **Programming error (memory-safety bug):** `copy_input()` in
   [src/return_overwrite.c](src/return_overwrite.c) allocates a 32-byte stack
   buffer (`char buffer[32]`) and reads `count` bytes (up to 128) via
   `receive_bytes()` without checking `count <= sizeof(buffer)` unless `FIXED`
   is defined.
2. **Exploitation primitive:** **Saved-return-address overwrite** (stack-based
   control-flow redirection). A contiguous write past `buffer` corrupts the
   caller's saved frame pointer and the saved return address on the stack. When
   `copy_input()` executes its epilogue `ret`, the CPU pops the corrupted stack
   word into the instruction pointer.
3. **Measurement oracle (`redirect_target()`):** `redirect_target()` is an
   unreachable, side-effect-free function already present in the binary that
   writes `TARGET: control flow redirected\n` and terminates with `_exit(42)`.
   Using an in-binary oracle isolates *instruction-pointer redirection* from:
   - **Code injection / shellcode**, which would conflate control-flow transfer
     with executable stack/heap permissions (`NX` / `W^X`).
   - **External `libc` or multi-gadget ROP chains**, which depend on library
     versions and additional gadget availability.

## Difference 1: Within-Environment Mitigation Comparison (x86-64)

All four binaries are built from [src/return_overwrite.c](src/return_overwrite.c)
with the same compiler, optimization level and base flags
(`-O0 -g -fno-omit-frame-pointer -fno-optimize-sibling-calls -U_FORTIFY_SOURCE -fcf-protection=none`
and `-Wl,-z,relro,-z,now,-z,noexecstack`). Each variant changes one variable at a
time:

| Binary | Stack Protector | ELF Type / PIE | Bounds Check | Saved-Return Offset | Observed Outcome (`attack.input`, 56 B) |
|---|---|---|---|---|---|
| `overwrite_plain` | `-fno-stack-protector` | `ET_EXEC` (`-fno-pie -no-pie`) | absent | 40 bytes | **Redirected:** enters `redirect_target()`, prints marker, exits with status `42` |
| `overwrite_canary` | `-fstack-protector-all` | `ET_EXEC` (`-fno-pie -no-pie`) | absent | 56 bytes | **Detected post-write:** `__stack_chk_fail()` before `ret`, `SIGABRT` (`-6`) |
| `overwrite_pie` | `-fno-stack-protector` | `ET_DYN` (`-fPIE -pie`) | absent | 40 bytes | **Address fault:** static non-PIE address unmapped under ASLR, `SIGSEGV` (`-11`) |
| `overwrite_fixed` | `-fno-stack-protector` | `ET_EXEC` (`-fno-pie -no-pie`) | `-DFIXED` | 40 bytes | **Prevented pre-write:** rejected before reading input, exits with status `2` |

In addition to `safe.input` (16 bytes of `A`, which must return normally with
status `0` on all four binaries), `overwrite_plain` is also tested against
`padding.input` (56 bytes of `A`, equal in length to `attack.input`). That
negative control faults with `SIGSEGV` (`-11`) and never prints the target
marker, demonstrating that status `42` requires deliberate target-address
placement rather than overflow length alone.

### What Each Mitigation Actually Changes

- **Stack Canary (`overwrite_canary`):** The compiler inserts an 8-byte guard
  word between `buffer` and saved `%rbp`, shifting the saved return address from
  offset `40` to `56`. Because `receive_bytes()` writes contiguously from
  `buffer[0]`, reaching the saved return address overwrites the guard. In the
  epilogue, the guard comparison fails and calls `__stack_chk_fail()` before
  `ret` executes. This is **post-write detection**, not prevention of the
  out-of-bounds write.
- **PIE + ASLR (`overwrite_pie`):** The stack frame layout is identical to
  `overwrite_plain` (saved `%rip` at offset `40`), and `ret` still loads the
  corrupted stack slot into `%rip`. However, because the executable is linked as
  `ET_DYN` and relocated by the kernel per process (`randomize_va_space = 2`),
  the static non-PIE address (`0x401...`) points to unmapped memory and triggers
  a page fault (`SIGSEGV`).
- **Explicit Bounds Check (`overwrite_fixed`):** Checking `count > sizeof(buffer)`
  before `receive_bytes()` repairs the programming error on this path; no
  out-of-bounds stack write occurs.

## Difference 2: Architectural & Toolchain Evolution (Legacy i386 vs. Modern x86-64)

Connecting this experiment to the repository's [Debian 7 `i386` / Debian 13 `amd64` baseline](../../docs/BASELINE-COMPARISON.md)
highlights the structural differences between classical 32-bit stack
exploitation and modern 64-bit systems:

| Dimension | Legacy 32-bit (`i386`, Debian 7 GCC 4.7.2) | Modern 64-bit (`x86-64`, Debian 13 GCC 14.2.0) |
|---|---|---|
| **Frame geometry (`overwrite_plain`)** | `buffer` at `%ebp - 0x28`; 4B saved `%ebp` at `%ebp`; 4B saved `%eip` at `%ebp + 4` (**offset `44`**) | `buffer` at `%rbp - 0x20`; 8B saved `%rbp` at `%rbp`; 8B saved `%rip` at `%rbp + 8` (**offset `40`**, `56` with canary) |
| **Payload structure & length** | **48 bytes:** `44B 'A'` + `4B redirect_target` (`0x0804862c`) | **56 bytes:** `40B 'A'` + `8B alignment_ret` (`0x4012c9`) + `8B redirect_target` (`0x4011a6`) |
| **Argument passing** | Passed on the stack above `%ebp + 8` (`cdecl`) | First six integer/pointer arguments in `%rdi, %rsi, %rdx, %rcx, %r8, %r9` |
| **Stack alignment at `call`** | Direct 4-byte return-address overwrite (`44B + 4B target`) suffices | Strictly 16-byte aligned before `call` (`%rsp % 16 == 8` at function entry; requires 8B `alignment_ret` before target) |
| **Toolchain default (Lab 03)** | Emits non-PIE `ET_EXEC` (`0x08048...`) without stack guard by default | Emits PIE `ET_DYN` and stack protection by default; requires `-fno-stack-protector -fno-pie -no-pie` to recreate `overwrite_plain` |

### Why x86-64 Requires the `alignment_ret` Gadget

On 32-bit `i386`, overwriting saved `%eip` directly with the 4-byte target
function address redirects execution cleanly. On 64-bit `x86-64`, the System V
AMD64 ABI requires `%rsp` to be a multiple of 16 immediately before a `call`
instruction. Because `call` pushes an 8-byte return address, any function entry
point expects `%rsp % 16 == 8` (which becomes `%rsp % 16 == 0` after
`push %rbp`).

When `copy_input()` returns via `ret`, it pops 8 bytes from the stack without a
corresponding `call`. Jumping directly to a function entry leaves
`%rsp % 16 == 0` upon entry. To satisfy the ABI entry invariant, the 56-byte
x86-64 payload places a single 8-byte `ret` instruction address (`alignment_ret`,
extracted from `copy_input`'s epilogue) at offset `40` and the address of
`redirect_target` at offset `48`:

```text
[ 40 bytes 'A' (32B buffer + 8B saved %rbp) ][ 8B alignment_ret ][ 8B target_address ]
```

The first `ret` pops `alignment_ret` and advances `%rsp` by 8 bytes; executing
that `ret` pops `target_address` into `%rip` with `%rsp % 16 == 8` (verified in
the collector's GDB trace via `LAB05_TARGET_RSP_MOD16=8`).

## Attacker Assumptions and Limits

1. **White-box static addresses:** `alignment_ret` and `target_address` are read
   from the local non-PIE `overwrite_plain` binary via `objdump` and `nm`
   (`address_source: "local non-PIE build artifacts; not an information disclosure"`).
2. **Scope of the PIE result:** The crash in `overwrite_pie` proves only that a
   hardcoded non-PIE address fails under ASLR. It does **not** prove that PIE
   alone prevents exploitation when combined with a separate runtime pointer
   disclosure (information leak) that reveals the randomized text base.
3. **Scope of the Canary result:** The abort in `overwrite_canary` applies to a
   **contiguous linear overflow** starting before the guard. It does not model
   arbitrary indexed writes or canary disclosure bugs.

## Build, Standalone Reproduction, and Automated Capture

Build the four variants locally:

```bash
make -C labs/05-return-address-overwrite
```

### Standalone Reproduction Outside GDB

To verify the mechanism directly from the shell without GDB, extract the `ret`
gadget and `redirect_target()` symbol from `overwrite_plain` and feed the
56-byte payload to each binary:

```bash
python3 - <<'EOF'
import re, struct, subprocess

lab = "labs/05-return-address-overwrite"
nm_out = subprocess.check_output(["nm", "--defined-only", f"{lab}/overwrite_plain"], text=True)
target = int(re.search(r"^([0-9a-fA-F]+)\s+[tT]\s+redirect_target$", nm_out, re.M).group(1), 16)
obj_out = subprocess.check_output(["objdump", "-d", "--disassemble=copy_input", f"{lab}/overwrite_plain"], text=True)
ret = int(re.findall(r"^\s*([0-9a-f]+):\s+c3\s+ret\s*$", obj_out, re.M)[0], 16)

payload = b"A" * 40 + struct.pack("<QQ", ret, target)
padding = b"A" * len(payload)

for name, data in (
    ("overwrite_plain (attack)", payload),
    ("overwrite_plain (padding control)", padding),
    ("overwrite_canary (attack)", payload),
    ("overwrite_pie (attack)", payload),
    ("overwrite_fixed (attack)", payload),
):
    binary = f"{lab}/{name.split()[0]}"
    res = subprocess.run([binary, str(len(data))], input=data, capture_output=True)
    print(f"{name:34s} -> returncode={res.returncode:4d} stdout={res.stdout.decode().strip()!r}")
EOF
```

### Automated Evidence Capture

Run the collector in a fresh output directory:

```bash
python3 scripts/capture-return-overwrite.py host /tmp/overwrite-host
```

The collector builds all four binaries in an isolated directory, checks ELF
headers (`ET_EXEC` vs. `ET_DYN`, `__stack_chk_fail`, `GNU_RELRO`, `BIND_NOW`,
`GNU_STACK RW`), measures the saved-return offset per binary via GDB, records
the `redirect_target()` entry stack alignment (`LAB05_TARGET_RSP_MOD16=8`),
executes 27 trials with core dumps disabled, and writes `observations.json`,
`payload.json`, `SHA256SUMS` and `COMPLETE`.
