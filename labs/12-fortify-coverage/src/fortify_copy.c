/* Lab 12 — when is a buffer copy ACTUALLY checked? FORTIFY coverage vs. the flag.
 *
 * _FORTIFY_SOURCE asks gcc/glibc to replace unsafe memory calls with bounds-checked
 * variants (memcpy -> __memcpy_chk) that abort on overflow. But the check is emitted
 * only when the compiler can determine the DESTINATION's size at the call site
 * (via __builtin_object_size / __builtin_dynamic_object_size). Whether that holds
 * depends on HOW the destination is known there, not on the flag alone. This file
 * exposes the same copy in three "size-knowledge" variants so the emitted code and
 * its runtime effect can be compared across FORTIFY levels:
 *
 *   static   : the destination is a fixed-size array the compiler sees in this
 *              function (char buf[DEST_SIZE]) — size is a compile-time constant.
 *   runtime  : the destination is malloc(cap) where cap is a runtime value — the
 *              object size is not a compile-time constant.
 *   crosstu  : the copy happens in sink_copy() (sink.c) into a buffer whose size is
 *              private to that other translation unit; nothing here can see it.
 *
 * Each function is noinline and external so the collector can disassemble it
 * individually and read whether the call is `memcpy` or `__memcpy_chk` (the emitted
 * link), and run it with an overflow to see whether the copy aborts (the effective
 * link). The gap between "FORTIFY requested" and "this copy is checked" is thereby
 * measured per variant and per level, not asserted from the flag.
 *
 * No external target, no information disclosure: the source bytes come from argv,
 * the copy is into the process's own buffer, and an overflow aborts or corrupts
 * only this process. The stack protector is disabled in the Makefile so that the
 * ONLY thing that can abort an overflow is an effective __memcpy_chk; this isolates
 * FORTIFY from the canary (studied separately in Lab 04).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sink.h"

#define DEST_SIZE 32

/* noinline so each variant is an independently disassemblable symbol whose emitted
 * call (memcpy vs __memcpy_chk) the collector can read directly. */

/* static destination: size is a compile-time constant the compiler sees here. */
__attribute__((noinline))
int copy_static(const char *src, size_t n)
{
	char buf[DEST_SIZE];
	memcpy(buf, src, n);
	return buf[0];
}

/* runtime destination: malloc(cap) with cap a runtime value, so the object size is
 * not a compile-time constant at this call site. */
__attribute__((noinline))
int copy_runtime(const char *src, size_t cap, size_t n)
{
	char *buf = malloc(cap);
	if (!buf)
		return -1;
	memcpy(buf, src, n);
	int first = buf[0];
	free(buf);
	return first;
}

/* cross-TU destination: copy_crosstu owns a fixed-size buffer, but the memcpy runs
 * inside sink_copy (sink.c), which receives only the pointer and cannot see the
 * size. sink.c is a separate TU without LTO, so the copy there is never checked —
 * even though the buffer here is as "known" as the static variant's. The coverage
 * gap is a property of WHERE the memcpy is, not of the buffer. */
__attribute__((noinline))
int copy_crosstu(const char *src, size_t n)
{
	char buf[DEST_SIZE];
	return sink_copy(buf, src, n);
}

int main(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr, "usage: %s <static|runtime|crosstu> <n> [src] [cap]\n", argv[0]);
		return 2;
	}
	const char *mode = argv[1];
	size_t n = (size_t)strtoul(argv[2], NULL, 10);
	/* Opaque source of at least n bytes; argv[3] if given, else a long literal.
	 * Using argv keeps the source length unknown to the optimizer. */
	static const char filler[] =
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
	const char *src = argc > 3 ? argv[3] : filler;
	/* Runtime capacity parsed from argv (default via strtoul of a string, not the
	 * integer literal), so the compiler cannot fold it into a compile-time size. */
	size_t cap = (size_t)strtoul(argc > 4 ? argv[4] : "32", NULL, 10);

	int r;
	if (strcmp(mode, "static") == 0)
		r = copy_static(src, n);
	else if (strcmp(mode, "runtime") == 0)
		r = copy_runtime(src, cap, n);
	else if (strcmp(mode, "crosstu") == 0)
		r = copy_crosstu(src, n);
	else {
		fprintf(stderr, "unknown mode: %s\n", mode);
		return 2;
	}

	printf("completed mode=%s n=%zu first=%d\n", mode, n, r);
	return 0;
}
