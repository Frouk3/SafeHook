#include "SafeHook.h"

#if defined(_MSC_VER)
    #define NOINLINE __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
    #define NOINLINE __attribute__((noinline))
#else
    #define NOINLINE
#endif

// Mid-assembly hooking, or mid-assembly function hooking.
// This technique can be hooked anywhere in the function, except jcc(if not allocated near the region where it should be hooked, in x64 might become a problem, x86 forgives you) or loop instructions

NOINLINE int multiply(int a, int b)
{
    return a * b;
}

NOINLINE void __cdecl midasm_multiply(SafeHook::CTX& ctx)
{
#if SAFEHOOK_X64
    int &a = ctx.rcx.i32; // First argument in RCX
    int &b = ctx.rdx.i32; // Second argument in RDX
#else
    int &a = *(int*)(ctx.esp().i32 + 0x4); // assuming we did not hook after prologue, then our first argument is at ESP + 4, and second argument is at ESP + 8
    int &b = *(int*)(ctx.esp().i32 + 0x8);
#endif
    // modifying parameters before calling the original function
    a = 1;
    b = 1337;
}

// Clarification:
// Mid-assembly hooking can be hooked ANYWHERE in the function
// Be careful when you're trying to use registers
// It hooks right into the "target" function, so you need to mind that registers are stored as is before executing the original code

void test_mid_asm_hook()
{
    int result = multiply(2, 3);
    printf("Original multiply(2, 3) = %d\n", result);

    SafeHook::MidAsmHook hook(multiply, midasm_multiply);
    int hooked_result = multiply(2, 3);
    printf("Hooked multiply(2, 3) = %d\n", hooked_result);

    hook.Disable();
    int unhooked_result = multiply(2, 3);
    printf("After unhooking multiply(2, 3) = %d\n", unhooked_result);
}

int main()
{
    test_mid_asm_hook();
    return 0;
}