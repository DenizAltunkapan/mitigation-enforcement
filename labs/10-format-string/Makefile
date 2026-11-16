CC ?= gcc
CFLAGS ?= -Wall -Wextra
LDFLAGS ?=
NO_PIE_FLAGS ?= $(shell printf 'int main(void){return 0;}\n' | \
	$(CC) -x c - -fno-pie -no-pie -o /dev/null >/dev/null 2>&1 && printf '%s' '-fno-pie -no-pie')
FCF_CFLAGS ?= $(shell printf 'int main(void){return 0;}\n' | \
	$(CC) -x c - -fcf-protection=none -o /dev/null >/dev/null 2>&1 && printf '%s' -fcf-protection=none)
# The two binaries differ only in _FORTIFY_SOURCE: the plain build lets a `%n`
# write land; the fortified build makes glibc reject `%n` from a writable format.
# Both variants use -O2 because glibc FORTIFY requires optimization. The only
# experimental difference is _FORTIFY_SOURCE. -Wno-format-security permits the
# deliberate user-controlled format string.
COMMON = -O2 -g -fno-omit-frame-pointer $(FCF_CFLAGS) -fno-stack-protector \
         $(NO_PIE_FLAGS) -Wno-format-security
TARGETS = format_plain format_fortified format_fixed

.PHONY: all clean
all: $(TARGETS)

format_plain: src/format_string.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(COMMON) -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -o $@ $<

format_fortified: src/format_string.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(COMMON) -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -o $@ $<

format_fixed: src/format_string.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(COMMON) -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -DFIXED_FORMAT -o $@ $<

clean:
	rm -f $(TARGETS)
