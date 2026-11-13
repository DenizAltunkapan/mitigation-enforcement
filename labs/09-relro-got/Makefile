CC ?= gcc
CFLAGS ?= -Wall -Wextra
LDFLAGS ?=
NO_PIE_FLAGS ?= $(shell printf 'int main(void){return 0;}\n' | \
	$(CC) -x c - -fno-pie -no-pie -o /dev/null >/dev/null 2>&1 && printf '%s' '-fno-pie -no-pie')
FCF_CFLAGS ?= $(shell printf 'int main(void){return 0;}\n' | \
	$(CC) -x c - -fcf-protection=none -o /dev/null >/dev/null 2>&1 && printf '%s' -fcf-protection=none)
# The two binaries differ only in RELRO: `now` resolves and locks the GOT at
# startup (full RELRO), `lazy` leaves it writable (partial RELRO). Non-PIE so the
# GOT slot address is fixed and read from the artifacts, as in Labs 05 and 08.
# Stack protection is off and CET disabled to isolate the GOT write itself.
COMMON = -O0 -g -fno-omit-frame-pointer -U_FORTIFY_SOURCE $(FCF_CFLAGS) \
         -fno-stack-protector $(NO_PIE_FLAGS)
TARGETS = got_full got_partial

.PHONY: all clean
all: $(TARGETS)

got_full: src/got_write.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(COMMON) -Wl,-z,relro,-z,now -o $@ $<

got_partial: src/got_write.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(COMMON) -Wl,-z,relro,-z,lazy -o $@ $<

clean:
	rm -f $(TARGETS)
