# Lab 07 - Runtime Execution Permission (W^X)

Research question: Lab 03 recorded that the binary requests a non-executable
stack (`GNU_STACK RW`) and that the CPU advertises NX, but ran no runtime test
and stated that neither the ELF request nor the CPU flag establishes runtime
enforcement. This lab supplies that measurement for one anonymous mapping: at
run time, does that page's execute permission decide whether bytes in it can run,
independent of the bytes themselves, and is W^X (never writable and executable at
once) a hardware guarantee or a software policy? The scope is deliberately
narrow — an anonymous `mmap`/`mprotect` mapping, not loaded segments, stacks or
heaps, and one host's kernel policy.

This is a local, white-box systems-security experiment on x86-64 Linux. Run it
as an ordinary user on a review host or in a disposable VM. ASLR is irrelevant
to this result and is left at the host setting.

## Concepts

The program copies one small in-binary function into a fresh anonymous mapping
and tries to call it under a chosen page protection:

1. **Oracle:** `oracle()` in [src/wx_probe.c](src/wx_probe.c) is a leaf function
   with no relocations that returns the marker value `42`. Its machine code is
   copied byte for byte, so the same instructions are executed (or faulted on)
   in every mode. Reaching it prints `CALLED 42`. It performs no shell, file,
   socket or external-library action: this is a permission probe, not shellcode
   and not an exploit.
2. **Staging:** each mapping is created writable so the oracle can be copied in,
   then switched to the mode's protection with `mprotect`. This mirrors how a
   JIT or an exploit stages code and isolates the execute bit as the one
   variable.
3. **Observation:** the call either runs (`CALLED 42`, exit 0), is refused by the
   kernel at `mprotect` (`REJECTED mprotect`, exit 3), or faults with `SIGSEGV`
   when the page is not executable. No debugger is needed.

## Modes

| Mode | Protection | Expected outcome |
|---|---|---|
| `rw` | `PROT_READ \| PROT_WRITE` | **Fault:** the non-executable page is not runnable, `SIGSEGV` |
| `rx` | `PROT_READ \| PROT_EXEC` | **Runs:** the identical bytes execute, marker `42`, exit 0 |
| `rwx` | `PROT_READ \| PROT_WRITE \| PROT_EXEC` | **Policy-dependent:** runs where W^X is unenforced, or `mprotect` is rejected where it is enforced |

`rw` and `rx` differ only in the execute bit on the very same bytes, so a `rw`
fault together with an `rx` success shows that execution permission, not the
region, governs whether code runs. `rwx` separates a hardware NX guarantee from
a software W^X policy: NX makes a non-executable page fault regardless, but
whether a page may be *both* writable and executable is a kernel/LSM decision,
not a CPU one.

## Build and capture

Build the probe locally:

```bash
make -C labs/07-execution-permission
./labs/07-execution-permission/wx_probe rx    # prints CALLED 42
./labs/07-execution-permission/wx_probe rw    # killed by SIGSEGV
```

### Automated evidence capture

Run the collector in a fresh output directory:

```bash
python3 scripts/capture-wx.py host /tmp/wx-host
```

The collector builds the probe, checks the ELF requests a non-executable stack,
disassembles `oracle` to confirm the copied span is exactly that function and
ends in `ret` (so a fault or success reflects executing the oracle, not stray
bytes), then runs each of the three modes three times (9 trials) with core dumps
disabled. It records whether each mode was deterministic across its repeats and
writes `observations.json`, `finding.json`, `SHA256SUMS` and `COMPLETE`. A
failed or unexpected run keeps its partial evidence without `COMPLETE`.

Export verified portable text evidence from one or more complete captures:

```bash
python3 scripts/export-wx.py /tmp/wx-host --output /tmp/wx.json
```

The exporter verifies the full manifest and exact artifact coverage and refuses
to overwrite an existing JSON file. The committed [portable evidence](evidence/)
records a host capture including the oracle disassembly and the finding.

## Limits

1. **Policy, not universality.** The `rwx` result reports this host's policy.
   A different kernel, an LSM such as SELinux (`execmem`), a `pax`/hardened
   configuration, or a seccomp filter can reject a writable-executable mapping.
   The lab records which outcome occurred; it does not claim either is universal.
2. **mmap/mprotect, not the binary.** This measures anonymous page permissions,
   not the loaded segments of the executable itself, and not stack or heap
   execution specifically.
3. **NX is a CPU feature; W^X is a policy.** A non-executable page faults because
   of NX, but the absence of a writable-executable restriction is a software
   choice. The lab keeps those two claims separate.
4. **No exploit.** Reaching the oracle shows that copied bytes ran under a
   permission, nothing about controlling a real program's flow; that is the
   subject of Labs 05 and 06.

## Relation to the other labs

Lab 03 observed the non-executable-stack ELF request and the NX CPU flag but
left runtime enforcement untested. Lab 07 measures it directly. Labs 05 and 06
deliberately use an in-binary oracle to avoid conflating control-flow redirection
with executable-memory permissions; this lab isolates exactly that permission
question on its own. Measured on x86-64; a legacy i386 comparison is out of scope
here, as that environment's default QEMU CPU does not advertise NX (see Lab 03).
