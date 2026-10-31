CC ?= gcc
CFLAGS ?= -Wall -Wextra
LDFLAGS ?=
NO_PIE_FLAGS ?= $(shell printf 'int main(void){return 0;}\n' | \
	$(CC) -x c - -fno-pie -no-pie -o /dev/null >/dev/null 2>&1 && printf '%s' '-fno-pie -no-pie')
FCF_CFLAGS ?= $(shell printf 'int main(void){return 0;}\n' | \
	$(CC) -x c - -fcf-protection=none -o /dev/null >/dev/null 2>&1 && printf '%s' -fcf-protection=none)
# Pin the debug/frame layout for this white-box exercise. ASLR is unchanged.
# CET and fortification are disabled consistently to isolate the chosen cases.
COMMON = -O0 -g -fno-omit-frame-pointer -fno-optimize-sibling-calls \
         -U_FORTIFY_SOURCE $(FCF_CFLAGS) -Wl,-z,relro,-z,now,-z,noexecstack
TARGETS = overwrite_plain overwrite_canary overwrite_pie overwrite_fixed

.PHONY: all clean
all: $(TARGETS)

overwrite_plain: src/return_overwrite.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(COMMON) -fno-stack-protector $(NO_PIE_FLAGS) -o $@ $<

overwrite_canary: src/return_overwrite.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(COMMON) -fstack-protector-all $(NO_PIE_FLAGS) -o $@ $<

overwrite_pie: src/return_overwrite.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(COMMON) -fno-stack-protector -fPIE -pie -o $@ $<

overwrite_fixed: src/return_overwrite.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(COMMON) -fno-stack-protector $(NO_PIE_FLAGS) -DFIXED -o $@ $<

clean:
	rm -f $(TARGETS)
