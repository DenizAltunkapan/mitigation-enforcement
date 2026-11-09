CC ?= gcc
CFLAGS ?= -Wall -Wextra
LDFLAGS ?=
NO_PIE_FLAGS ?= $(shell printf 'int main(void){return 0;}\n' | \
	$(CC) -x c - -fno-pie -no-pie -o /dev/null >/dev/null 2>&1 && printf '%s' '-fno-pie -no-pie')
FCF_CFLAGS ?= $(shell printf 'int main(void){return 0;}\n' | \
	$(CC) -x c - -fcf-protection=none -o /dev/null >/dev/null 2>&1 && printf '%s' -fcf-protection=none)
# A non-executable stack is requested so stack shellcode cannot run; that is the
# control the lab relies on. The binary is non-PIE so the reused gadget addresses
# are fixed and read from local build artifacts (as in Lab 05). Stack protection
# is off to isolate the return-address overwrite; CET is disabled consistently.
COMMON = -O0 -g -fno-omit-frame-pointer -fno-optimize-sibling-calls \
         -U_FORTIFY_SOURCE $(FCF_CFLAGS) -fno-stack-protector $(NO_PIE_FLAGS) \
         -Wl,-z,relro,-z,now,-z,noexecstack
TARGETS = code_reuse code_reuse_fixed

.PHONY: all clean
all: $(TARGETS)

code_reuse: src/code_reuse.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(COMMON) -o $@ $<

code_reuse_fixed: src/code_reuse.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(COMMON) -DFIXED -o $@ $<

clean:
	rm -f $(TARGETS)
