#include "core/syscalls.hpp"

namespace Syscalls
{
    // Get a syscall number and address for a given function.
    // Reference: https://www.crow.rip/crows-nest/mal/dev/inject/syscalls/indirect-syscalls
    SYSCALL FindSyscall(UINT_PTR pNtFuncAddr)
    {
        SYSCALL syscall;

        BYTE syscallOpcode[2] = {0x0F, 0x05};

        syscall.dwSSN = ((PBYTE)(pNtFuncAddr + 4))[0];
        syscall.pAddr = pNtFuncAddr + 0x12;

        if (memcmp(syscallOpcode, (const void*)syscall.pAddr, sizeof(syscallOpcode)) != 0)
        {
            return {0};
        }

        return syscall;
    }
}