#include "core/syscalls.hpp"

namespace Syscalls
{
    // Get a syscall number and address for a given function.
    SYSCALL FindSyscall(HMODULE hNTDLL, LPCSTR lpNtFunc)
    {
        SYSCALL syscall;

        UINT_PTR pNtFuncAddr = (UINT_PTR)nullptr;
        BYTE syscallOpcode[2] = {0x0F, 0x05};

        pNtFuncAddr = (UINT_PTR)GetProcAddress(hNTDLL, lpNtFunc);
        if (!pNtFuncAddr)
        {
            return syscall;
        }

        syscall.dwSSN = ((PBYTE)(pNtFuncAddr + 4))[0];
        syscall.pAddr = pNtFuncAddr + 0x12;

        if (memcmp(syscallOpcode, (const void*)syscall.pAddr, sizeof(syscallOpcode)) != 0)
        {
            return {0};
        }

        return syscall;
    }
}