# Lab 09 - GOT Overwrite Under Partial vs Full RELRO

Research question: the control-flow labs 05, 06 and 08 all redirect through the
saved return address. The GOT (Global Offset Table) is a different control-flow target — every
imported library function is called through a writable pointer. Does RELRO
decide, at run time, whether that pointer can be overwritten: is the GOT writable
under partial RELRO and read-only under full RELRO?

This is a local, white-box systems-security experiment on x86-64 Linux. Run it as
an ordinary user on a review host or in a disposable VM. The GOT write has
undefined behavior in C; its outcome is an empirical observation for a specific
compiler, linker and binary configuration.

The binaries in Labs 05–08 already link with full RELRO. This lab measures what
that flag actually prevents.

## Concepts

The program exposes one bug and one target:

1. **The target:** `puts()` is called through its GOT slot — a pointer the dynamic
   linker fills in. Overwriting that slot redirects the next `puts()` call.
2. **The write:** [src/got_write.c](src/got_write.c) writes the address of an
   in-binary `oracle()` into the `puts` GOT slot and then calls `puts()`. The
   oracle prints a marker and exits `42`; it performs no shell, file, socket or
   external action. Reaching it shows the redirected call landed there.
3. **The mitigation:** RELRO. Partial RELRO (`-z relro -z lazy`) keeps the GOT
   writable so symbols can bind lazily on first call. Full RELRO (`-z relro -z
   now`) resolves every symbol at startup and then maps the GOT read-only.

The GOT slot address is read from the local non-PIE build artifacts with
`objdump -R`, exactly as Labs 05 and 08 read static addresses; this is not an
information disclosure. The build is non-PIE so the slot address is fixed. Full
and partial RELRO lay the GOT out differently, so each binary has its own slot.

## Cases

| Case | Binary | Linker | Observed outcome |
|---|---|---|---|
| `partial` | `got_partial` | `-z relro -z lazy` | **GOT writable:** the write succeeds, `puts()` jumps to the oracle, exit `42` |
| `full` | `got_full` | `-z relro -z now` | **GOT read-only:** the write to the mapped-read-only GOT faults, `SIGSEGV` (`-11`) |

The two cases differ only in RELRO, so a `partial` success and a `full` fault
isolate RELRO as the deciding factor. Reaching the oracle under partial RELRO is
GOT-based control-flow redirection, a target distinct from the saved return
address that Labs 05–08 attack.

## Build and capture

Build the two variants locally:

```bash
make -C labs/09-relro-got
```

### Automated evidence capture

Run the collector in a fresh output directory:

```bash
python3 scripts/capture-relro.py host /tmp/relro-host
```

The collector builds both binaries, checks each is a non-PIE `ET_EXEC` with a
`GNU_RELRO` segment, no stack guard, and the expected `BIND_NOW` (full) or its
absence (partial), reads each binary's `puts` GOT slot from its own relocations,
then runs the two cases three times each (6 trials) with core dumps disabled. It
requires each case to be deterministic across its repeats and writes
`observations.json`, `payload.json`, `finding.json`, `SHA256SUMS` and `COMPLETE`.
A failed or unexpected run keeps its partial evidence without `COMPLETE`.

Export verified portable text evidence from one or more complete captures:

```bash
python3 scripts/export-relro.py /tmp/relro-host --output /tmp/relro.json
```

The exporter verifies the full manifest and exact artifact coverage and refuses
to overwrite an existing JSON file. The committed [portable evidence](evidence/)
records a host capture including the finding.

## Attacker assumptions and limits

1. **White-box static address.** The GOT slot is read from the local non-PIE
   build artifacts, not from a leak. A PIE binary would first require the
   disclosure studied in Lab 06.
2. **One slot, one call.** The lab overwrites a single GOT entry and triggers one
   call. It does not model a full GOT-based ROP/PLT attack or lazy-binding races.
3. **RELRO is a loader/linker property.** The result is about where the dynamic
   linker maps the GOT, not about the CPU. It says nothing about CET, canaries or
   NX, which the other labs cover.
4. **No real target.** Reaching the oracle shows a redirected in-binary call, not
   arbitrary code execution and not an attack on a real system.

## Relation to the other labs

Labs 05–08 hijack the saved return address. Lab 09 hijacks a different
control-flow pointer, the GOT, and measures the mitigation that specifically
protects it. Full RELRO — the configuration all of this repository's binaries
already use — makes the GOT read-only at run time, turning the overwrite into a
fault; partial RELRO leaves it open. As in the overwrite labs, the vulnerable
write is the root cause, and locking the writable pointer is the structural
defense. Measured on x86-64; CET and stack protection are disabled to isolate the
GOT write.
