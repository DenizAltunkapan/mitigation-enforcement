/*
 * Lab 06 - Defeating PIE with an information leak (local, white-box).
 *
 * Lab 05 showed that a hardcoded non-PIE target address faults under PIE+ASLR
 * (SIGSEGV) because the randomized text base is unknown per process. This lab
 * adds the missing primitive: a controlled text-pointer disclosure. The leak
 * and the overflow happen in the SAME process, so the disclosed base is the one
 * the overflow runs against. With the base known, the saved return address is
 * overwritten with a target computed relative to it, and redirection succeeds.
 *
 * Why one process: under ASLR the text base differs between executions. Leaking
 * from one process and overflowing another would feed a stale base and fault,
 * which is precisely the Lab 05 negative result. A realistic attacker uses a
 * leak and a memory-corruption bug within one session; this program models that
 * by disclosing a code pointer and then taking overflow input in one run.
 *
 * Everything is a synthetic local exercise. The "leak" is an explicit,
 * in-program disclosure of a code pointer; it stands in for a real bug class
 * (format-string %p, uninitialized read) without modelling any specific CVE.
 * The destination is an in-binary oracle, redirect_target(), which performs no
 * shell, subprocess, file or network action. No shellcode, no external libc or
 * ROP gadgets, no real target.
 *
 * Invocation:
 *   pie_leak session
 *       1. Print "LEAK <hex>", the runtime address of reference_symbol(), a code
 *          pointer into the randomized PIE text segment (the disclosure).
 *       2. Read a decimal byte count as the first stdin line, then read exactly
 *          that many bytes into a 32-byte stack buffer (the bug) and return.
 *          1 <= count <= 160.
 *   pie_leak leak
 *       Print the leak only, then exit 0. Used to show the base varies per run.
 *
 * Build-time switch (see Makefile):
 *   FIXED  -> adds the bounds check that repairs the bug (no overflow path).
 *
 * redirect_target() and reference_symbol() share the text segment, so their
 * link-time distance is constant and identical in every process. The attacker
 * computes, from the single session leak:
 *     redirect_target_runtime = leaked(reference_symbol) + (redirect - reference)
 * where (redirect - reference) is read from the local build artifacts, exactly
 * as Lab 05 reads static addresses with nm/objdump. The link-time delta is not
 * an information disclosure; only the runtime base is.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* A stable, side-effect-free code symbol used only as a leak reference point.
 * It is never called; its runtime address is the disclosed pointer. */
__attribute__((used, noinline))
void reference_symbol(void)
{
    /* An opaque body so the compiler cannot fold or discard the function. */
    __asm__ __volatile__("");
}

/* The in-binary measurement oracle: unreachable by normal control flow, with no
 * external side effects. Reaching it is the positive observation. */
__attribute__((used, noinline, noreturn))
static void redirect_target(void)
{
    static const char message[] = "TARGET: control flow redirected\n";
    ssize_t written = write(STDOUT_FILENO, message, sizeof(message) - 1);
    _exit(written == (ssize_t)(sizeof(message) - 1) ? 42 : 43);
}

/* Disclosure primitive: print a code pointer into the randomized text segment.
 * A real bug (format string, uninitialized read) would surface such a pointer
 * unintentionally; here it is explicit so the experiment is deterministic. */
static int leak(void)
{
    if (printf("LEAK %p\n", (void *)&reference_symbol) < 0)
        return 70;
    return 0;
}

__attribute__((noinline))
static int receive_bytes(void *destination, size_t count)
{
    size_t received = 0;
    while (received < count) {
        ssize_t n = read(STDIN_FILENO, (char *)destination + received,
                         count - received);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
        received += (size_t)n;
    }
    return 0;
}

/* Read one decimal line from stdin (the attacker-chosen length). Kept separate
 * so the overflow buffer below holds only the raw payload bytes. */
static int read_count(size_t *out)
{
    char line[32];
    size_t used = 0;
    for (;;) {
        char c;
        ssize_t n = read(STDIN_FILENO, &c, 1);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
        if (c == '\n')
            break;
        if (used + 1 >= sizeof(line))
            return -1;
        line[used++] = c;
    }
    line[used] = '\0';
    char *end;
    errno = 0;
    unsigned long value = strtoul(line, &end, 10);
    if (errno || end == line || *end || value == 0 || value > 160)
        return -1;
    *out = (size_t)value;
    return 0;
}

__attribute__((noinline))
static int overflow(size_t count)
{
    char buffer[32];
#ifdef FIXED
    if (count > sizeof(buffer)) {
        fputs("rejected: input exceeds buffer capacity\n", stderr);
        return 2;
    }
#endif
    /* Deliberate bug unless FIXED: count may exceed sizeof(buffer). The write is
     * contiguous from buffer[0], so a long enough input reaches the saved frame
     * pointer and saved return address. */
    if (receive_bytes(buffer, count) != 0) {
        fputs("input incomplete\n", stderr);
        return 3;
    }
    printf("copy completed: %lu bytes, first byte %u\n",
           (unsigned long)count, (unsigned char)buffer[0]);
    return 0;
}

static int session(void)
{
    int rc = leak();
    if (rc != 0)
        return rc;
    size_t count;
    if (read_count(&count) != 0) {
        fputs("invalid byte count\n", stderr);
        return 64;
    }
    int result = overflow(count);
    if (result == 0)
        puts("returned from overflow");
    return result;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    if (argc == 2 && strcmp(argv[1], "session") == 0)
        return session();
    if (argc == 2 && strcmp(argv[1], "leak") == 0)
        return leak();

    fputs("usage: pie_leak session | pie_leak leak\n", stderr);
    return 64;
}
