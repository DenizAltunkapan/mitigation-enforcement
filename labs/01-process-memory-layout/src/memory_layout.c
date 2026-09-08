#include <stdio.h>
#include <stdlib.h>

int global_initialized = 7;
int global_uninitialized;

static int static_initialized = 11;
static int static_uninitialized;

static void helper_function(void)
{
}

static void print_maps(void)
{
    FILE *maps = fopen("/proc/self/maps", "r");
    char line[256];

    if (maps == NULL) {
        perror("fopen /proc/self/maps");
        return;
    }

    puts("\n/proc/self/maps:");
    while (fgets(line, sizeof(line), maps) != NULL) {
        fputs(line, stdout);
    }

    fclose(maps);
}

int main(void)
{
    int stack_local = 3;
    void *heap_chunk = malloc(32);

    if (heap_chunk == NULL) {
        perror("malloc");
        return 1;
    }

    printf("main:                  %p\n", (void *)main);
    printf("helper_function:       %p\n", (void *)helper_function);
    printf("global_initialized:    %p\n", (void *)&global_initialized);
    printf("global_uninitialized:  %p\n", (void *)&global_uninitialized);
    printf("static_initialized:    %p\n", (void *)&static_initialized);
    printf("static_uninitialized:  %p\n", (void *)&static_uninitialized);
    printf("heap allocation:       %p\n", heap_chunk);
    printf("stack local:           %p\n", (void *)&stack_local);
    printf("printf from libc:      %p\n", (void *)printf);

    print_maps();
    free(heap_chunk);
    return 0;
}
