/*
 * Lab 09 - GOT overwrite under partial vs full RELRO, local white-box.
 *
 * The control-flow labs 05, 06 and 08 all redirect through the saved return
 * address. The GOT (Global Offset Table) is a different control-flow target: each imported
 * library function is called through a writable pointer that the dynamic linker
 * fills in. Overwriting a GOT entry redirects the next call to that function.
 *
 * RELRO decides whether that is possible at run time:
 *   - Partial RELRO (-z relro -z lazy): the GOT stays writable so lazy binding
 *     can resolve symbols on first use. A GOT overwrite succeeds.
 *   - Full RELRO (-z relro -z now): the linker resolves every symbol at startup
 *     and then maps the GOT read-only. A GOT overwrite faults.
 *
 * The binaries in Labs 05-08 build with full RELRO; this lab
 * measures what that actually prevents. The program writes the address of an
 * in-binary oracle into a chosen GOT slot and then makes the corresponding
 * library call. The oracle performs no shell, file, socket or external action;
 * reaching it shows the redirected call landed there, nothing more.
 *
 * The target GOT slot address is read from the local non-PIE build artifacts
 * with objdump, exactly as Labs 05 and 08 read static addresses; this is not an
 * information disclosure. The build is non-PIE so the slot address is fixed.
 *
 * Invocation:
 *   got_write <hex-address-of-puts-GOT-slot>
 *       1. Write &oracle into that slot (the vulnerable action).
 *       2. Call puts(). Under partial RELRO the call reaches the oracle and the
 *          process exits 42; under full RELRO the write to the read-only GOT
 *          faults with SIGSEGV before the call.
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* An unreachable, side-effect-free oracle. Reaching it is the positive signal. */
__attribute__((used, noinline, noreturn)) static void oracle(void)
{
    static const char message[] = "TARGET: GOT call redirected\n";
    ssize_t written = write(STDOUT_FILENO, message, sizeof(message) - 1);
    _exit(written == (ssize_t)(sizeof(message) - 1) ? 42 : 43);
}

int main(int argc, char **argv)
{
    char *end;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc != 2 || argv[1][0] < '0' || argv[1][0] > '9') {
        fputs("usage: got_write <hex-address-of-puts-GOT-slot>\n", stderr);
        return 64;
    }
    errno = 0;
    unsigned long long address = strtoull(argv[1], &end, 16);
    if (errno || *end || address == 0) {
        fputs("invalid GOT slot address\n", stderr);
        return 64;
    }

    /* The vulnerable write: redirect puts()'s GOT slot to the oracle. On a full
     * RELRO binary the GOT page is read-only here, so this instruction faults. */
    void **slot = (void **)(uintptr_t)address;
    *slot = (void *)&oracle;

    /* The call that follows the redirected pointer under partial RELRO. */
    puts("hello");
    puts("returned normally");
    return 0;
}
