/* Cross-translation-unit copy for Lab 12. Declared here, defined in sink.c. The
 * destination is supplied BY THE CALLER as a bare pointer, so sink.c cannot see its
 * size and, compiled as a separate TU without LTO, the compiler cannot emit a
 * FORTIFY check for the memcpy inside sink_copy — regardless of the level. This is
 * the "destination size opaque across a TU boundary" variant. */
#ifndef LAB12_SINK_H
#define LAB12_SINK_H

#include <stddef.h>

/* Copy n bytes of src into the caller-provided dst and return dst[0]. The size of
 * dst is unknown in this translation unit. */
int sink_copy(char *dst, const char *src, size_t n);

#endif
