CC ?= gcc
CFLAGS ?= -O0 -g -Wall -Wextra -fno-omit-frame-pointer

.PHONY: all clean

all: stack_frames

stack_frames: src/stack_frames.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f stack_frames
