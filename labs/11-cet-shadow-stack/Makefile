CC ?= gcc
CFLAGS ?= -Wall -Wextra
LDFLAGS ?=
# Non-PIE so the saved-return-address layout and &hijack are stable, as in Labs
# 05/08/09. Probe support so the Makefile degrades on a toolchain without -no-pie.
NO_PIE_FLAGS ?= $(shell printf 'int main(void){return 0;}\n' | \
	$(CC) -x c - -fno-pie -no-pie -o /dev/null >/dev/null 2>&1 && printf '%s' '-fno-pie -no-pie')

# The two binaries differ ONLY in whether CET is requested at build time:
#   cet_full  -fcf-protection=full : emits the CET ELF note (IBT + SHSTK) and
#             endbr64 landing pads; this binary asks to be shadow-stack protected.
#   cet_none  -fcf-protection=none : the uninstrumented reference; no CET note.
# Everything else is identical and deliberately minimal (no stack protector, no
# FORTIFY) so the ONLY control-flow guarantee under test is the shadow stack. The
# research claim is about the gap between cet_full's REQUEST and what actually
# happens at runtime, not about any other mitigation.
COMMON = -O0 -g -fno-omit-frame-pointer -U_FORTIFY_SOURCE -fno-stack-protector \
         $(NO_PIE_FLAGS)
TARGETS = cet_full cet_none

.PHONY: all clean
all: $(TARGETS)

cet_full: src/shadow_stack.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(COMMON) -fcf-protection=full -o $@ $<

cet_none: src/shadow_stack.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(COMMON) -fcf-protection=none -o $@ $<

clean:
	rm -f $(TARGETS)
