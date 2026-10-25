CC ?= gcc
CFLAGS ?= -O0 -g -Wall -Wextra -fno-omit-frame-pointer
LDFLAGS ?=
# Suppress fortified libc checks in every variant to isolate the stack guard.
COMMON = -U_FORTIFY_SOURCE -Wl,-z,relro,-z,now,-z,noexecstack
TARGETS = stack_unprotected stack_canary stack_fixed

.PHONY: all clean
all: $(TARGETS)

stack_unprotected: src/stack_copy.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(COMMON) -fno-stack-protector -o $@ $<

stack_canary: src/stack_copy.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(COMMON) -fstack-protector-all -o $@ $<

stack_fixed: src/stack_copy.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(COMMON) -fstack-protector-all -DFIXED -o $@ $<

clean:
	rm -f $(TARGETS)
