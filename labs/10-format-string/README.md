# Lab 10 - Format-String Disclosure, Write Primitive and FORTIFY

Research question: a format string under attacker control is both a read and a
write primitive. Does a `%p` walk disclose stack memory, does a `%n` conversion
act as a memory write, and does glibc's `_FORTIFY_SOURCE=2` stop the `%n` write?

This is a local, white-box systems-security experiment on x86-64 Linux. Run it as
an ordinary user on a review host or in a disposable VM. The vulnerability is a
`printf(user_input, &test_variable)` call. The repaired variant uses
`printf("%s", user_input)`. Outcomes are empirical observations for a specific
compiler, C library and build configuration.

This lab demonstrates an unintended disclosure and a write to a supplied local
pointer, without a stack buffer overflow. Lab 06 assumes a different leak: a
same-process text pointer that reveals a PIE base. Lab 10 does not produce it.

## Concepts

The program calls `printf(argv[1], &target)` — the format string is
attacker-controlled, while the test program supplies the pointer.

1. **Disclosure (`%p`):** repeated `%p` conversions consume argument locations,
   including stack locations after the register arguments. The program plants
   a recognizable numeric marker on the stack; a walk of `%p` conversions
   reveals it, so the leak is unambiguous rather than "some address appeared".
2. **Write (`%n`):** `%n` writes the number of bytes printed so far through a
   pointer argument. The program supplies a pointer to a local test variable;
   after `AAAA%n`, the variable contains `4` and the program exits `42`.
3. **Mitigation (FORTIFY):** built with `_FORTIFY_SOURCE=2`, `printf` becomes
   `__printf_chk`, and glibc rejects a `%n` whose format string is in writable
   memory, printing a `%n in writable segment(s) detected` diagnostic (the exact
   wording is glibc-version dependent) and aborting (`SIGABRT`) before any write
   is attempted.
4. **Repair (fixed format):** `printf("%s", argv[1])` treats the same input as
   data. The `%n` characters print literally and the test variable stays zero.

## Cases

| Case | Binary | Input | Observed outcome |
|---|---|---|---|
| `leak` | `format_plain` | a `%p` walk | **Disclosure:** the planted stack marker appears in the output, exit 0 |
| `write` | `format_plain` | `AAAA%n` | **Write succeeds:** the local test variable becomes `4`, exit `42` |
| `fortify` | `format_fortified` | `AAAA%n` | **Rejected:** glibc detects `%n` and aborts, `SIGABRT` (`-6`) |
| `fixed` | `format_fixed` | `AAAA%n` | **Repaired:** prints `AAAA%n` literally, exit `0` |

The `write` and `fortify` cases run the same input against two `-O2` builds
that differ only in `_FORTIFY_SOURCE`. The successful-write-versus-abort
contrast isolates FORTIFY. The fortified binary calls `__printf_chk`; the
plain one calls `printf`.

## Build and capture

Build the three variants locally:

```bash
make -C labs/10-format-string
```

### Automated evidence capture

Run the collector in a fresh output directory:

```bash
python3 scripts/capture-format-string.py host /tmp/format-string-host
```

The collector builds all three binaries, checks each is a non-PIE `ET_EXEC` and that
only the fortified build imports `__printf_chk`, then runs the four cases three
times each (12 trials) with core dumps disabled. It requires each case to be
deterministic across its repeats and writes `observations.json`, `payload.json`,
`finding.json`, `SHA256SUMS` and `COMPLETE`. A failed or unexpected run keeps its
partial evidence without `COMPLETE`.

Export verified portable text evidence from one or more complete captures:

```bash
python3 scripts/export-format-string.py /tmp/format-string-host --output /tmp/format-string.json
```

The exporter verifies the full manifest and exact artifact coverage and refuses
to overwrite an existing JSON file. The committed [portable evidence](evidence/)
records a host capture including the finding.

## Attacker assumptions and limits

1. **The primitive, not a targeted exploit.** This measures a disclosure and a
   `%n` write to a pointer deliberately supplied by the program. The attacker
   does not choose an arbitrary address; obtaining control of a write target
   without a supplied pointer is out of scope.
2. **FORTIFY is a glibc build-time choice.** The result is about `_FORTIFY_SOURCE`
   and the writable-format `%n` check in this glibc, not a CPU feature; it says
   nothing about canaries, NX, RELRO or CET.
3. **A single disclosure and a single local write.** The lab does not chain a leak
   into a targeted write, which is how a real format-string exploit proceeds.
4. **No real target.** The disclosed marker and the local write are synthetic
   and local; nothing here attacks a real program.

## Relation to the other labs

Labs 05, 06 and 08 start from a buffer overflow; Lab 09 models a direct GOT
write. Lab 10 uses a different bug class, an uncontrolled format string. Its
disclosure illustrates a general risk but is not the PIE-base leak assumed in
Lab 06. FORTIFY rejects one exploit path; the fixed-format build removes the
format-string vulnerability. Measured on x86-64; CET and stack protection are
disabled to isolate the format-string behavior.
