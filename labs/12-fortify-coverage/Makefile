CC ?= gcc
CFLAGS ?= -Wall -Wextra
LDFLAGS ?=

# FORTIFY_SOURCE requires an optimizing build (-O1+); the mitigation is simply not
# emitted at -O0, so this lab builds at -O2. Each binary differs ONLY in the
# requested FORTIFY level: off (explicitly undefined, since this distro's gcc spec
# defaults to a non-zero level), level 2, and level 3. -U first so the per-target
# -D is the only level in effect.
#
# The stack protector is turned OFF deliberately: it would abort a stack overflow
# (SIGABRT) independently of FORTIFY and confound the "did FORTIFY catch it?"
# signal. With -fno-stack-protector, the only thing that can abort an overflow is
# an emitted-and-effective __memcpy_chk, so the runtime signal is attributable to
# FORTIFY alone. (A separate lab, 04, studies the canary itself.)
#
# sink.c is a SEPARATE translation unit with no LTO, so the destination size in the
# crosstu variant genuinely cannot cross the TU boundary — that is the point of the
# variant. Building its object at each level keeps the whole program at one level.
BASE = -O2 -g -fno-stack-protector $(CFLAGS)
SRC = src/fortify_copy.c
SINK = src/sink.c
TARGETS = fortify_off fortify_l2 fortify_l3

.PHONY: all clean
all: $(TARGETS)

fortify_off: $(SRC) $(SINK) src/sink.h
	$(CC) $(BASE) -U_FORTIFY_SOURCE $(LDFLAGS) -Isrc -o $@ $(SRC) $(SINK)

fortify_l2: $(SRC) $(SINK) src/sink.h
	$(CC) $(BASE) -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 $(LDFLAGS) -Isrc -o $@ $(SRC) $(SINK)

fortify_l3: $(SRC) $(SINK) src/sink.h
	$(CC) $(BASE) -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 $(LDFLAGS) -Isrc -o $@ $(SRC) $(SINK)

clean:
	rm -f $(TARGETS)
