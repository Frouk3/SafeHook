#include "SafeHook.h"

#if defined(_MSC_VER)
    #define NOINLINE __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
    #define NOINLINE __attribute__((noinline))
#else
    #define NOINLINE
#endif

// Inline hooking, or function hooking.
// Basic interception technique that allows you to modify the behavior of a function

NOINLINE int add(int a, int b)
{
    return a + b;
}

NOINLINE int hook_add(int a, int b)
{
    printf("Ughh. %d + %d", a, b);

    return 1337;
}

void test_inline_hook()
{
    // Original function call
    int result = add(2, 3);
    printf("Original add(2, 3) = %d\n", result);

    // Hook the add function
    void *original_add = nullptr;
    SafeHook::Hook hook(add, (void*)&hook_add, (void**)&original_add);

    // Call the hooked function
    result = add(2, 3);
    printf("Hooked add(2, 3) = %d\n", result);

    // Unhook the function
    hook.Disable();

    // Call the original function again
    result = add(2, 3);
    printf("After unhooking add(2, 3) = %d\n", result);
}

int main()
{
    test_inline_hook();
    return 0;
}