#include <stdint.h>
#include <stdio.h>

#if defined(__x86_64__)
#define READ_STACK_POINTER(value) __asm__ volatile("mov %%rsp, %0" : "=r"(value))
#define READ_BASE_POINTER(value) __asm__ volatile("mov %%rbp, %0" : "=r"(value))
#elif defined(__i386__)
#define READ_STACK_POINTER(value) __asm__ volatile("mov %%esp, %0" : "=r"(value))
#define READ_BASE_POINTER(value) __asm__ volatile("mov %%ebp, %0" : "=r"(value))
#else
#define READ_STACK_POINTER(value) value = 0
#define READ_BASE_POINTER(value) value = 0
#endif

__attribute__((noinline)) static void inspect_frame(int first, int second,
                                                    int third)
{
    int local_a = 10;
    int local_b = 20;
    uintptr_t stack_pointer = 0;
    uintptr_t base_pointer = 0;
    char buffer[16] = "frame";

    READ_STACK_POINTER(stack_pointer);
    READ_BASE_POINTER(base_pointer);

    printf("inspect_frame address: %p\n", (void *)inspect_frame);
    printf("argument first:        %d at %p\n", first, (void *)&first);
    printf("argument second:       %d at %p\n", second, (void *)&second);
    printf("argument third:        %d at %p\n", third, (void *)&third);
    printf("local_a:               %d at %p\n", local_a, (void *)&local_a);
    printf("local_b:               %d at %p\n", local_b, (void *)&local_b);
    printf("buffer:                %p\n", (void *)buffer);
    printf("stack pointer:         0x%jx\n", (uintmax_t)stack_pointer);
    printf("base pointer:          0x%jx\n", (uintmax_t)base_pointer);
    printf("frame address:         %p\n", __builtin_frame_address(0));
    printf("return address:        %p\n", __builtin_return_address(0));
}

int main(void)
{
    puts("calling inspect_frame(1, 2, 3)");
    inspect_frame(1, 2, 3);
    return 0;
}
