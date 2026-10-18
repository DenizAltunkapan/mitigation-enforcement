#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void print_marker(const char *label)
{
    char local_buffer[32];

    snprintf(local_buffer, sizeof(local_buffer), "%s", label);
    printf("%s marker: %p\n", local_buffer, (void *)print_marker);
    printf("%s stack object: %p\n", local_buffer, (void *)local_buffer);
}

int main(int argc, char **argv)
{
    printf("program path: %s\n", argv[0]);
    printf("argc: %d\n", argc);
    printf("main: %p\n", (void *)main);
    printf("memcpy symbol: %p\n", (void *)(uintptr_t)memcpy);

    print_marker("mitigation-probe");
    return 0;
}
