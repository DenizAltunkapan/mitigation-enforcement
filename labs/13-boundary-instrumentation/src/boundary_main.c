/* Lab 13 — Partial instrumentation across a shared-library boundary.
 *
 * Research question: when the main executable and a linked shared library are
 * built with different stack-protector settings (both / main-only / lib-only /
 * neither), which overflows are actually detected at run time?
 *
 * Both components expose the same 32-byte linear stack copy:
 *   in_main : copy_in_main() in this executable
 *   in_lib  : copy_in_lib() in libboundary_{on,off}.so
 *
 * Modes:
 *   safe   : in-bounds copy (n <= 32) -> completes normally (exit 0)
 *   attack : out-of-bounds copy (n > 32) -> detected by canary (SIGABRT) iff
 *            the overflowing component was instrumented; otherwise raw SIGSEGV
 *   fixed  : explicit bounds-checked copy -> rejected pre-write (exit 2) in
 *            every configuration, regardless of compiler instrumentation
 *
 * No external target, no shellcode, no disclosure: the overflow corrupts only
 * this process's own stack frame to measure per-component guard coverage.
 */
#include "boundary_lib.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__attribute__((noinline))
int copy_in_main(const char *src, size_t n)
{
	char buf[BOUNDARY_BUF_SIZE];
	memcpy(buf, src, n);
	return (unsigned char)buf[0];
}

__attribute__((noinline))
int copy_in_main_fixed(const char *src, size_t n)
{
	char buf[BOUNDARY_BUF_SIZE];
	if (n > sizeof(buf)) {
		fputs("rejected: input exceeds buffer capacity\n", stderr);
		return -2;
	}
	memcpy(buf, src, n);
	return (unsigned char)buf[0];
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	if (argc < 4) {
		fprintf(stderr, "usage: %s <in_main|in_lib> <safe|attack|fixed> <n> [src]\n",
			argv[0]);
		return 64;
	}
	const char *location = argv[1];
	const char *mode = argv[2];
	char *end = NULL;
	unsigned long parsed = strtoul(argv[3], &end, 10);
	if (!end || *end != '\0' || parsed == 0 || parsed > 256) {
		fputs("invalid byte count\n", stderr);
		return 64;
	}
	size_t n = (size_t)parsed;

	static const char filler[257] =
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
	const char *src = argc > 4 ? argv[4] : filler;

	int use_fixed;
	if (strcmp(mode, "fixed") == 0)
		use_fixed = 1;
	else if (strcmp(mode, "safe") == 0 || strcmp(mode, "attack") == 0)
		use_fixed = 0;
	else {
		fprintf(stderr, "unknown mode: %s\n", mode);
		return 64;
	}

	int r;
	if (strcmp(location, "in_main") == 0)
		r = use_fixed ? copy_in_main_fixed(src, n) : copy_in_main(src, n);
	else if (strcmp(location, "in_lib") == 0)
		r = use_fixed ? copy_in_lib_fixed(src, n) : copy_in_lib(src, n);
	else {
		fprintf(stderr, "unknown location: %s\n", location);
		return 64;
	}

	if (r == -2)
		return 2;

	printf("completed location=%s mode=%s n=%zu first=%d\n", location, mode, n, r);
	return 0;
}
