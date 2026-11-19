/* Shared-library boundary copy for Lab 13.
 *
 * The main executable links against either libboundary_on.so (built with
 * -fstack-protector-strong) or libboundary_off.so (built with
 * -fno-stack-protector). Both expose the exact same two functions so the
 * experiment isolates which component's instrumentation protects an overflow
 * inside the library's stack frame.
 */
#ifndef LAB13_BOUNDARY_LIB_H
#define LAB13_BOUNDARY_LIB_H

#include <stddef.h>

#define BOUNDARY_BUF_SIZE 32

/* Vulnerable stack copy inside the shared library (no bounds check). */
int copy_in_lib(const char *src, size_t n);

/* Explicit source-level repair inside the shared library (bounds check). */
int copy_in_lib_fixed(const char *src, size_t n);

#endif
