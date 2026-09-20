#include "SafeHook.h"

// this hook used to hook right into an address, have a trampoline, exit label and uses the good old __asm to write the hook code

#if SAFEHOOK_X64
    #error "This example is for 32-bit only. Please compile in 32-bit mode." // "64-bit inline assembly is not safe to use" - Microsoft
#endif

SafeHook::InlineHook inline_for_12313213;

void __declspec(naked) __cdecl inline_hook()
{
    __asm
    {
        mov eax, 1337
        jmp inline_for_12313213.m_exit
    }
}

int __declspec(naked) __cdecl f_12313213(int a, int b)
{
    __asm
    {
        push ebp                // +1
        mov ebp, esp            // +3
        sub esp, 10             // +3  

        mov eax, [ebp + 8]      // +3 
        mov ebx, [ebp + 12]     // +3
        add eax, ebx            // +2

        leave                   // +1
        ret                     // +1
    }
}

int main()
{
    new(&inline_for_12313213) SafeHook::InlineHook((void*)((unsigned long)f_12313213 + 7), (void*)inline_hook, 8);

    int result = f_12313213(2, 3);
    printf("Result of f_12313213(2, 3) = %d\n", result);

    inline_for_12313213.Disable();

    result = f_12313213(2, 3);
    printf("Result of f_12313213(2, 3) after disabling hook = %d\n", result);

    return 0;
}