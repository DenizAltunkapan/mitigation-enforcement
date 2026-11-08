/*
 * Lab 07 - Runtime execution permission (W^X), local white-box.
 *
 * Lab 03 recorded that a binary requests a non-executable stack (GNU_STACK RW)
 * and that the CPU advertises NX, but explicitly performed no runtime test:
 * "Neither a non-executable-stack ELF request nor a CPU feature flag
 * establishes runtime execution-permission enforcement for a particular memory
 * region." This lab supplies that missing runtime measurement.
 *
 * The question, for one anonymous mapping: at run time, does that page's execute
 * permission decide whether bytes in it can be executed, independent of the bytes
 * themselves, and is W^X (never writable and executable at once) a hardware
 * guarantee or a software policy? The scope is an anonymous mmap/mprotect
 * mapping on one host, not loaded segments, stacks or heaps.
 *
 * Method: copy one small, self-contained function's machine code into a fresh
 * anonymous mapping, set a chosen protection, and attempt to call it. The copied
 * function is an in-binary oracle: it returns a fixed marker value and touches
 * no shell, file, socket or external library. This is not shellcode and not an
 * exploit; it is a controlled permission probe.
 *
 * Modes (argv[1]):
 *   rw   PROT_READ|PROT_WRITE               non-executable page -> expect a fault
 *   rx   PROT_READ|PROT_EXEC                executable page     -> expect success
 *   rwx  PROT_READ|PROT_WRITE|PROT_EXEC     writable+executable -> policy-dependent
 *
 * Outcomes are reported on stdout and as an exit status so a parent can record
 * them without a debugger:
 *   CALLED <marker>   and exit 0   - the bytes executed
 *   REJECTED mprotect and exit 3   - the kernel refused the mapping (W^X policy)
 *   (no marker; the process is killed by SIGSEGV)   - the page was not executable
 *
 * Determinism: outcomes depend on the page protection and the host policy, not
 * on addresses or timing. ASLR is irrelevant here and left at the host setting.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define MARKER 42

/* The oracle: a leaf function with no relocations at -O0, so a byte copy of its
 * body is independently callable. `used`/`noinline` keep it intact; the trailing
 * marker function bounds its length without relying on symbol-table order. */
__attribute__((used, noinline)) static int oracle(void)
{
    return MARKER;
}

__attribute__((used, noinline)) static void oracle_end(void)
{
    __asm__ __volatile__("");
}

typedef int (*oracle_fn)(void);

/* Bytes to copy: the span from `oracle` to the next function. At -O0 with no
 * sibling-call optimization the compiler lays these out in source order, so the
 * difference is the oracle's body. The collector additionally disassembles the
 * binary to confirm the span covers exactly `oracle` and ends in `ret`. */
static size_t oracle_len(void)
{
    uintptr_t start = (uintptr_t)&oracle;
    uintptr_t end = (uintptr_t)&oracle_end;
    return (size_t)(end - start);
}

static int probe(int prot)
{
    size_t len = oracle_len();
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0)
        return 70;
    size_t size = (len + (size_t)page - 1) & ~((size_t)page - 1);

    /* Map writable first so the oracle can be copied in, then switch to the
     * requested protection. This mirrors how a just-in-time compiler or an
     * exploit stages code, and isolates the execute bit as the single variable. */
    void *mapping = mmap(NULL, size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) {
        perror("mmap");
        return 71;
    }
    memcpy(mapping, (const void *)&oracle, len);

    if (mprotect(mapping, size, prot) != 0) {
        printf("REJECTED mprotect prot=%d: %s\n", prot, strerror(errno));
        munmap(mapping, size);
        return 3;
    }

    oracle_fn call = (oracle_fn)mapping;
    int value = call(); /* SIGSEGV here if the page is not executable. */
    printf("CALLED %d\n", value);
    munmap(mapping, size);
    return value == MARKER ? 0 : 1;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc != 2) {
        fputs("usage: wx_probe <rw|rx|rwx>\n", stderr);
        return 64;
    }
    if (strcmp(argv[1], "rw") == 0)
        return probe(PROT_READ | PROT_WRITE);
    if (strcmp(argv[1], "rx") == 0)
        return probe(PROT_READ | PROT_EXEC);
    if (strcmp(argv[1], "rwx") == 0)
        return probe(PROT_READ | PROT_WRITE | PROT_EXEC);
    fputs("usage: wx_probe <rw|rx|rwx>\n", stderr);
    return 64;
}
