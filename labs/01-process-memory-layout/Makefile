CC ?= gcc
CFLAGS ?= -O0 -g -Wall -Wextra -fno-omit-frame-pointer

.PHONY: all clean

all: memory_layout

memory_layout: src/memory_layout.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f memory_layout
