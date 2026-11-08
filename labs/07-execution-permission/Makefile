CC ?= gcc
CFLAGS ?= -Wall -Wextra
LDFLAGS ?=
FCF_CFLAGS ?= $(shell printf 'int main(void){return 0;}\n' | \
	$(CC) -x c - -fcf-protection=none -o /dev/null >/dev/null 2>&1 && printf '%s' -fcf-protection=none)
# One binary, selected at run time by argument. Built at -O0 with frame pointers
# and no sibling-call optimization so the oracle is a contiguous, relocation-free
# leaf whose bytes can be copied and called from a fresh mapping. A non-executable
# stack is requested; CET is disabled consistently with the other labs. The
# experiment is about mmap/mprotect page permissions, not the binary's own layout.
COMMON = -O0 -g -fno-omit-frame-pointer -fno-optimize-sibling-calls \
         -U_FORTIFY_SOURCE $(FCF_CFLAGS) -Wl,-z,relro,-z,now,-z,noexecstack
TARGETS = wx_probe

.PHONY: all clean
all: $(TARGETS)

wx_probe: src/wx_probe.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(COMMON) -o $@ $<

clean:
	rm -f $(TARGETS)
