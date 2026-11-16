/*
 * Lab 10 - Format-string vulnerability: disclosure, a write primitive, and the
 * mitigation that stops the write and a fixed-format repair.
 *
 * A format string under attacker control is both a read and a write primitive.
 * This lab measures both on one synthetic program, and the glibc mitigation:
 *
 *   leak:     Repeated `%p` conversions consume argument locations. A planted
 *             marker appears in the output on this measured build, showing an
 *             unintended disclosure. It is not the text-pointer leak of Lab 06.
 *   write:    `%n` writes the number of bytes printed so far through an
 *             explicitly supplied pointer to a local test variable.
 *   fortified: built with `_FORTIFY_SOURCE=2`, glibc rejects `%n` whenever the
 *             format string lives in writable memory and aborts (SIGABRT) before
 *             the test variable can be changed.
 *   fixed:    printf("%s", input) treats the same text as data. No conversion
 *             is performed, so the local test variable remains unchanged.
 *
 * The marker and test variable make both effects observable. This is not a
 * targeted exploit: the program supplies the writable pointer deliberately.
 *
 * Invocation (one format string argument):
 *   format_string '<format>'
 *     Prints `<format>` through printf (the bug), then a newline.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* Recognizable numeric marker kept on the stack for the local disclosure test. */
#define STACK_MARKER 0x4c45414b4d41524bULL

int main(int argc, char **argv)
{
    volatile uint64_t marker = STACK_MARKER;
    int target = 0;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc != 2) {
        fputs("usage: format_string '<format>'\n", stderr);
        return 64;
    }

    /* The vulnerable path uses attacker-controlled format text and a supplied
     * local pointer, so the %n effect does not depend on a guessed stack slot.
     * The fixed path treats the input as data using a constant format. */
#ifdef FIXED_FORMAT
    printf("%s", argv[1]);
#else
    printf(argv[1], &target);
#endif
    printf("\n");

    if (target == 4) {
        fputs("TARGET: format write changed the test variable\n", stdout);
        return 42;
    }

    /* Keep the marker live across the printf so a leak walk can reach it. */
    return marker == STACK_MARKER ? 0 : 70;
}
