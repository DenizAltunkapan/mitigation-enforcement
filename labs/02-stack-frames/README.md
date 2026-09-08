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

## What To Compare

Measured baseline:

| Property | Historical LiveCD | Modern VM |
|---|---|---|
| Distribution | Ubuntu 7.04 (from LiveCD rootfs) | Debian GNU/Linux 13 (trixie) |
| Architecture | i386 | x86_64 |
| Kernel | 2.6.20-15-generic | 6.12.105+deb13-amd64 |
| GCC | 4.1.2 package in LiveCD manifest | Debian 14.2.0-19 |
| GDB | 6.6 package in LiveCD manifest | Debian 16.3-1 |
| glibc | 2.5 package in LiveCD manifest | 2.41-12+deb13u3 |

The preferred scriptable legacy baseline is the Debian 7 i386 VM created by
`scripts/setup-legacy-vm.sh`. Fill its runtime values after the VM install
completes and SSH on `localhost:2222` works.

| Question | Legacy 32-bit | Modern x86-64 |
|---|---|---|
| Which register is the stack pointer? | ESP | RSP |
| Which register is the base pointer? | EBP | RBP |
| Where is the return address stored? | typically at `[EBP + 4]`; run pending | saved RIP at `[RBP + 8]`, observed by GDB |
| Are function arguments on the stack or in registers? | stack by the i386 cdecl convention | first integer args in RDI, RSI, RDX, observed by GDB |
| Does the compiler keep a frame pointer? | expected with `-fno-omit-frame-pointer`; run pending | yes: RBP matched `__builtin_frame_address(0)` |

Modern GDB snapshot at the `inspect_frame` breakpoint:

```text
rsp  0x7fffffffe310
rbp  0x7fffffffe350
rip  0x55555555514a <inspect_frame+17>
rdi  0x1
rsi  0x2
rdx  0x3
saved rip = 0x5555555552dd
```

The stack dump showed the saved frame pointer followed by the saved return
address:

```text
0x7fffffffe350: 0x00007fffffffe360 0x00005555555552dd
```

Legacy note: the LiveCD kernel and rootfs were verified, but an interactive
serial shell was not available in the tested QEMU boot path. Use the
scriptable Debian 7 VM for the final legacy runtime measurements.

## Security Meaning

A stack buffer overflow becomes control-flow relevant when it can corrupt data
used by a later control transfer, such as a saved return address. This lab does
not exploit that. It only identifies where the relevant frame metadata lives.
