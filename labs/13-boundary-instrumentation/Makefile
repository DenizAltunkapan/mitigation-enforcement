CC ?= gcc
CFLAGS ?= -Wall -Wextra
LDFLAGS ?=

# Build two shared libraries (canary on vs. off) and four executables covering
# the 2x2 instrumentation matrix (both / main_only / lib_only / neither).
#
# -U_FORTIFY_SOURCE disables FORTIFY so the only compiler mitigation under study
# is the stack protector (-fstack-protector-strong vs. -fno-stack-protector).
# -fno-omit-frame-pointer and -fno-optimize-sibling-calls keep both copy frames
# intact and prevent tail-call elimination across the boundary.
# -Wl,-rpath,'$$ORIGIN' pins each executable to its sibling shared library in the
# same directory without relying on LD_LIBRARY_PATH.
BASE = -O2 -g -fno-omit-frame-pointer -fno-optimize-sibling-calls -U_FORTIFY_SOURCE $(CFLAGS)
RPATH = -Wl,-rpath,'$$ORIGIN'

LIBS = libboundary_on.so libboundary_off.so
BINS = boundary_both boundary_main_only boundary_lib_only boundary_neither
TARGETS = $(LIBS) $(BINS)

.PHONY: all clean
all: $(TARGETS)

libboundary_on.so: src/boundary_lib.c src/boundary_lib.h
	$(CC) $(BASE) -fPIC -shared -fstack-protector-strong $(LDFLAGS) -Isrc -o $@ src/boundary_lib.c

libboundary_off.so: src/boundary_lib.c src/boundary_lib.h
	$(CC) $(BASE) -fPIC -shared -fno-stack-protector $(LDFLAGS) -Isrc -o $@ src/boundary_lib.c

boundary_both: src/boundary_main.c src/boundary_lib.h libboundary_on.so
	$(CC) $(BASE) -fstack-protector-strong $(LDFLAGS) -Isrc -o $@ src/boundary_main.c -L. -lboundary_on $(RPATH)

boundary_main_only: src/boundary_main.c src/boundary_lib.h libboundary_off.so
	$(CC) $(BASE) -fstack-protector-strong $(LDFLAGS) -Isrc -o $@ src/boundary_main.c -L. -lboundary_off $(RPATH)

boundary_lib_only: src/boundary_main.c src/boundary_lib.h libboundary_on.so
	$(CC) $(BASE) -fno-stack-protector $(LDFLAGS) -Isrc -o $@ src/boundary_main.c -L. -lboundary_on $(RPATH)

boundary_neither: src/boundary_main.c src/boundary_lib.h libboundary_off.so
	$(CC) $(BASE) -fno-stack-protector $(LDFLAGS) -Isrc -o $@ src/boundary_main.c -L. -lboundary_off $(RPATH)

clean:
	rm -f $(TARGETS)
