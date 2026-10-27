# Lab 02 - Stack Frames and Calling Conventions

This lab observes what happens when one C function calls another.

It explains the register names that appear constantly in exploitation texts:

```text
x86 / 32-bit:    EIP, ESP, EBP
x86-64 / 64-bit: RIP, RSP, RBP
```

## Concepts

Important registers:

```text
EIP/RIP  instruction pointer: address of the next instruction
ESP/RSP  stack pointer: top of the current stack
EBP/RBP  base pointer: stable reference point for the current stack frame
```

On classical 32-bit x86 with frame pointers, a stack frame often looks like:

```text
higher addresses

function arguments
return address
saved EBP           <- EBP points here
local variables

lower addresses     <- ESP moves downward
```

On x86-64 Linux, the first integer/pointer arguments are normally passed in
registers instead of on the stack:

```text
RDI, RSI, RDX, RCX, R8, R9
```

This is one reason old 32-bit exploitation examples do not translate directly
to modern x86-64.

## Build

```bash
make
```

The lab is compiled with:

```text
-O0 -g -fno-omit-frame-pointer
```

That keeps stack frames easy to inspect. Later labs can compare this with
optimized builds and `-fomit-frame-pointer`.

## Run

```bash
./stack_frames
```

## Inspect With GDB

```bash
gdb ./stack_frames
```

Inside GDB:

```gdb
break inspect_frame
run
info registers
bt
frame 0
info frame
x/24gx $rsp
```

On 32-bit x86, use:

```gdb
x/24wx $esp
```

## Recorded comparison

The [verified Debian 7 / Debian 13 comparison](../../docs/BASELINE-COMPARISON.md)
includes three standalone runs per environment and one additional modern GDB
transcript, with identical source and recorded build variables.

| Observation | Debian 7 i386 | Debian 13 amd64 |
|---|---|---|
| Stack / frame registers | ESP / EBP | RSP / RBP |
| Frame pointer matches reported frame address | yes | yes |
| Argument evidence | addresses EBP+8, EBP+12, EBP+16 in run 1 | GDB shows RDI=1, RSI=2, RDX=3 at the breakpoint |
| Saved return-address slot | no debugger measurement | GDB reports saved RIP at RBP+8 |

The modern C argument variables have stack storage even though the breakpoint
shows their values in argument registers. Their printed addresses alone do not
establish the calling convention. The GDB run left ASLR enabled using
`set disable-randomization off`; it is separate from the standalone executions.
Do not combine addresses from those different processes into one stack diagram.

The [full modern transcript](../../docs/evidence/modern-session-2026-10-27.json)
contains register values, `info frame`, a memory dump and backtrace. Legacy GDB
is not installed in the recovered image, so its saved return-address slot remains
an inspection task rather than a new debugger result.

## Security Meaning

A stack buffer overflow becomes control-flow relevant when it can corrupt data
used by a later control transfer, such as a saved return address. This lab does
not exploit that. It only identifies where the relevant frame metadata lives.
