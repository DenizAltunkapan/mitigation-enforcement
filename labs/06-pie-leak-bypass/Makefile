CC ?= gcc
CFLAGS ?= -Wall -Wextra
LDFLAGS ?=
FCF_CFLAGS ?= $(shell printf 'int main(void){return 0;}\n' | \
	$(CC) -x c - -fcf-protection=none -o /dev/null >/dev/null 2>&1 && printf '%s' -fcf-protection=none)
# Both binaries are position-independent (ET_DYN) so ASLR randomizes the text
# segment: that is the whole point of the leak. Stack protection is off to
# isolate the return-address overwrite from the canary already studied in Lab 04
# and Lab 05. ASLR itself is unchanged. Frame layout is pinned for the GDB
# measurement; fortification and CET are disabled consistently.
COMMON = -O0 -g -fno-omit-frame-pointer -fno-optimize-sibling-calls \
         -U_FORTIFY_SOURCE $(FCF_CFLAGS) -fno-stack-protector -fPIE -pie \
         -Wl,-z,relro,-z,now,-z,noexecstack
TARGETS = pie_bypass pie_fixed

.PHONY: all clean
all: $(TARGETS)

pie_bypass: src/pie_leak.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(COMMON) -o $@ $<

pie_fixed: src/pie_leak.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(COMMON) -DFIXED -o $@ $<

clean:
	rm -f $(TARGETS)
