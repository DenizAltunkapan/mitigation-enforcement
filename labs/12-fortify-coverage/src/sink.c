/* Cross-TU copy for Lab 12. The destination is a bare pointer from the caller, so
 * its size is not visible here. Compiled as a separate translation unit without
 * LTO (see the Makefile), so __builtin_object_size(dst) is "unknown" and no FORTIFY
 * level can emit a check for this memcpy — the point of the crosstu variant. */
#include "sink.h"
#include <string.h>

int sink_copy(char *dst, const char *src, size_t n)
{
	memcpy(dst, src, n);
	return dst[0];
}
