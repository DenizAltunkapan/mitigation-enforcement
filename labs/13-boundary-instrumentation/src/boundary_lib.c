/* Shared-library side of Lab 13 (partial instrumentation across a library
 * boundary). Built twice: once with -fstack-protector-strong (libboundary_on.so)
 * and once with -fno-stack-protector (libboundary_off.so).
 *
 * -U_FORTIFY_SOURCE is set in the Makefile so FORTIFY does not confound the
 * stack-protector signal (FORTIFY is studied separately in Lab 12).
 */
#include "boundary_lib.h"

#include <stdio.h>
#include <string.h>

__attribute__((noinline))
int copy_in_lib(const char *src, size_t n)
{
	char buf[BOUNDARY_BUF_SIZE];
	memcpy(buf, src, n);
	return (unsigned char)buf[0];
}

__attribute__((noinline))
int copy_in_lib_fixed(const char *src, size_t n)
{
	char buf[BOUNDARY_BUF_SIZE];
	if (n > sizeof(buf)) {
		fputs("rejected: input exceeds buffer capacity\n", stderr);
		return -2;
	}
	memcpy(buf, src, n);
	return (unsigned char)buf[0];
}
