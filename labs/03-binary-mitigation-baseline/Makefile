CC ?= gcc
CFLAGS ?= -O0 -g -Wall -Wextra -fno-omit-frame-pointer
LDFLAGS ?=
NO_PIE_LDFLAGS ?= $(shell printf 'int main(void){return 0;}\n' | \
	$(CC) -x c - -no-pie -o /dev/null >/dev/null 2>&1 && printf '%s' -no-pie)

TARGETS := mitigation_default mitigation_hardened mitigation_no_pie

.PHONY: all clean inspect

all: $(TARGETS)

mitigation_default: src/mitigation_probe.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

mitigation_hardened: src/mitigation_probe.c
	$(CC) $(CFLAGS) -fstack-protector-all -D_FORTIFY_SOURCE=2 \
		-Wl,-z,relro,-z,now,-z,noexecstack $(LDFLAGS) -o $@ $<

mitigation_no_pie: src/mitigation_probe.c
	$(CC) $(CFLAGS) -fno-pie $(NO_PIE_LDFLAGS) $(LDFLAGS) -o $@ $<

inspect: all
	@./mitigation_default
	@echo
	@./mitigation_hardened
	@echo
	@./mitigation_no_pie

clean:
	rm -f $(TARGETS)
