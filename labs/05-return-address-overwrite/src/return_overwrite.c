#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* An intentionally unreachable, harmless destination for this local exercise.
 * No shell, subprocess, file access or network action is performed. */
__attribute__((used, noinline, noreturn))
static void redirect_target(void)
{
    static const char message[] = "TARGET: control flow redirected\n";
    ssize_t written = write(STDOUT_FILENO, message, sizeof(message) - 1);
    _exit(written == (ssize_t)(sizeof(message) - 1) ? 42 : 43);
}

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
    /* Deliberate bug in the three vulnerable builds: count may exceed 32. */
    if (receive_bytes(buffer, count) != 0) {
        fputs("input incomplete\n", stderr);
        return 3;
    }
    printf("copy completed: %lu bytes, first byte %u\n",
           (unsigned long)count, (unsigned char)buffer[0]);
    return 0;
}

int main(int argc, char **argv)
{
    char *end;
    unsigned long count;
    int result;
    if (argc != 2 || argv[1][0] < '0' || argv[1][0] > '9') {
        fputs("usage: return_overwrite <byte-count: 1..128>\n", stderr);
        return 64;
    }
    errno = 0;
    count = strtoul(argv[1], &end, 10);
    if (errno || *end || count == 0 || count > 128) {
        fputs("invalid byte count\n", stderr);
        return 64;
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    result = copy_input((size_t)count);
    if (result == 0)
        puts("returned from copy_input");
    return result;
}
