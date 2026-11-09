/*
 * Lab 08 - Code reuse under a non-executable stack, local white-box.
 *
 * Lab 07 measured that a page's execute permission is enforced: bytes on a
 * non-executable mapping do not run. That is exactly what defeats classic
 * stack shellcode. This lab shows the standard answer - reuse code that is
 * already executable - and is careful about the claim: NX stays in effect
 * throughout. Nothing here switches NX off. The overflow redirects control
 * into functions that are already mapped executable in the program's text,
 * so no page is ever both written and executed.
 *
 * The experiment chains three existing in-binary functions through a single
 * stack buffer overflow of the saved return address:
 *
 *   stage_one()  -> sets a state machine to 1 and prints "ONE"
 *   stage_two()  -> advances it to 2 only if it was 1, prints "TWO"
 *   oracle()     -> the in-binary measurement target; exits 42 only if the
 *                   state machine reached 2, i.e. the two gadgets ran in order
 *
 * Reaching oracle() with exit status 42 therefore proves that control flow was
 * redirected through a *chain* of reused functions in the right order - a
 * minimal return-oriented sequence - not a single jump and not injected code.
 * oracle() performs no shell, file, socket or external-library action; it is a
 * harmless in-binary target, not shellcode and not a real exploit.
 *
 * Modes are selected by the build and the input (see Makefile and the
 * collector). With FIXED the overflow is bounds-checked and no redirection is
 * possible, which is the root-cause repair.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Shared state the chain must advance in order. */
static int stage = 0;

/* Reused "gadgets": ordinary in-binary functions, each already executable. */
__attribute__((used, noinline)) static void stage_one(void)
{
    stage = 1;
    (void)!write(STDOUT_FILENO, "ONE\n", 4);
}

__attribute__((used, noinline)) static void stage_two(void)
{
    if (stage == 1)
        stage = 2;
    (void)!write(STDOUT_FILENO, "TWO\n", 4);
}

/* In-binary measurement oracle: reachable only by redirected control flow, and
 * status 42 only if the chain ran stage_one before stage_two. */
__attribute__((used, noinline, noreturn)) static void oracle(void)
{
    static const char message[] = "TARGET: control flow redirected\n";
    ssize_t written = write(STDOUT_FILENO, message, sizeof(message) - 1);
    if (written != (ssize_t)(sizeof(message) - 1))
        _exit(44);
    _exit(stage == 2 ? 42 : 43);
}

__attribute__((noinline)) static int receive_bytes(void *destination, size_t count)
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

__attribute__((noinline)) static int copy_input(size_t count)
{
    char buffer[32];
#ifdef FIXED
    if (count > sizeof(buffer)) {
        fputs("rejected: input exceeds buffer capacity\n", stderr);
        return 2;
    }
#endif
    /* Deliberate bug unless FIXED: count may exceed sizeof(buffer). */
    if (receive_bytes(buffer, count) != 0) {
        fputs("input incomplete\n", stderr);
        return 3;
    }
    printf("copy completed: %lu bytes\n", (unsigned long)count);
    return 0;
}

int main(int argc, char **argv)
{
    char *end;
    unsigned long count;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc != 2 || argv[1][0] < '0' || argv[1][0] > '9') {
        fputs("usage: code_reuse <byte-count: 1..256>\n", stderr);
        return 64;
    }
    errno = 0;
    count = strtoul(argv[1], &end, 10);
    if (errno || *end || count == 0 || count > 256) {
        fputs("invalid byte count\n", stderr);
        return 64;
    }
    int result = copy_input((size_t)count);
    if (result == 0)
        puts("returned from copy_input");
    return result;
}
