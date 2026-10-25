#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Keep the same input operation in both vulnerable builds. No payload addresses,
 * injected instructions or control-flow target are part of this experiment. */
__attribute__((noinline))
static int receive_bytes(void *destination, size_t count)
{
    size_t received = 0;
    while (received < count) {
        ssize_t n = read(STDIN_FILENO, (char *)destination + received,
                         count - received);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
        received += (size_t)n;
    }
    return 0;
}

__attribute__((noinline))
static int copy_input(size_t count)
{
    char buffer[32];
#ifdef FIXED
    if (count > sizeof(buffer)) {
        fputs("rejected: input exceeds buffer capacity\n", stderr);
        return 2;
    }
#endif
    if (receive_bytes(buffer, count) != 0) {
        fputs("input incomplete\n", stderr);
        return 3;
    }
    printf("copy completed: %lu bytes, first byte %u\n",
           (unsigned long)count, (unsigned char)buffer[0]);
    fflush(stdout);
    return 0;
}

int main(int argc, char **argv)
{
    int result;
    size_t count;
    if (argc != 2 || (strcmp(argv[1], "safe") && strcmp(argv[1], "overflow"))) {
        fputs("usage: stack_copy <safe|overflow>\n", stderr);
        return 64;
    }
    count = strcmp(argv[1], "safe") == 0 ? 16 : 128;
    result = copy_input(count);
    if (result == 0)
        puts("returned from copy_input");
    return result;
}
