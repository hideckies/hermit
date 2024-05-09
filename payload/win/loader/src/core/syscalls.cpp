#include "core/syscalls.hpp"

namespace Syscalls
{
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

    // From Image Base
    // Reference:
    // https://github.com/Cracked5pider/KaynLdr/blob/main/KaynInject/src/Syscall.c#L11
    WORD FindSyscallFromImageBase(
        PVOID pModuleBase,
        PIMAGE_EXPORT_DIRECTORY pExportDir,
        DWORD dwSysFuncHash
    ) {
        PDWORD  pdwAddressOfFunctions       = (PDWORD)((UINT_PTR)pModuleBase + pExportDir->AddressOfFunctions);
        PDWORD  pdwAddressOfNames           = (PDWORD)((UINT_PTR)pModuleBase + pExportDir->AddressOfNames);
        PWORD   pdwAddressOfNameOrdinals    = (PWORD)((UINT_PTR)pModuleBase + pExportDir->AddressOfNameOrdinals);

        WORD wSyscall = -1;

        for (WORD cx = 0; cx < pExportDir->NumberOfNames; cx++)
        {
            PCHAR pczFuncName  = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
            PVOID pFuncAddr = (PVOID)((PBYTE)pModuleBase + pdwAddressOfFunctions[pdwAddressOfNameOrdinals[cx]]);

            if (Utils::Convert::StrToHashA(pczFuncName) == dwSysFuncHash)
            {
                if (*((PBYTE)pFuncAddr) == 0x4c &&
                    *((PBYTE)pFuncAddr + 1) == 0x8b &&
                    *((PBYTE)pFuncAddr + 2) == 0xd1 &&
                    *((PBYTE)pFuncAddr + 3) == 0xb8 &&
                    *((PBYTE)pFuncAddr + 6) == 0x00 &&
                    *((PBYTE)pFuncAddr + 7) == 0x00
                ) {
                    __builtin_memcpy(&wSyscall, ((PBYTE)pFuncAddr + 4), 2);
                    return wSyscall;
                }

                if (*((PBYTE)pFuncAddr) == 0xe9)
                {
                    for (WORD idx = 1; idx <= 500; idx++)
                    {
                        if (*((PBYTE)pFuncAddr + idx * DOWN) == 0x4c
                            && *((PBYTE)pFuncAddr + 1 + idx * DOWN) == 0x8b
                            && *((PBYTE)pFuncAddr + 2 + idx * DOWN) == 0xd1
                            && *((PBYTE)pFuncAddr + 3 + idx * DOWN) == 0xb8
                            && *((PBYTE)pFuncAddr + 6 + idx * DOWN) == 0x00
                            && *((PBYTE)pFuncAddr + 7 + idx * DOWN) == 0x00)
                        {
                            __builtin_memcpy(&wSyscall, ((PBYTE)pFuncAddr + 4 + idx * DOWN), 2);
                            return wSyscall;

                        }

                        if (*((PBYTE)pFuncAddr + idx * UP) == 0x4c
                            && *((PBYTE)pFuncAddr + 1 + idx * UP) == 0x8b
                            && *((PBYTE)pFuncAddr + 2 + idx * UP) == 0xd1
                            && *((PBYTE)pFuncAddr + 3 + idx * UP) == 0xb8
                            && *((PBYTE)pFuncAddr + 6 + idx * UP) == 0x00
                            && *((PBYTE)pFuncAddr + 7 + idx * UP) == 0x00)
                        {
                            __builtin_memcpy(&wSyscall, ((PBYTE)pFuncAddr + 4 + idx * UP), 2);
                            return wSyscall;
                        }

                    }
                    return FALSE;
                }
                if (*((PBYTE)pFuncAddr + 3) == 0xe9)
                {
                    for (WORD idx = 1; idx <= 500; idx++)
                    {
                        if (*((PBYTE)pFuncAddr + idx * DOWN) == 0x4c
                            && *((PBYTE)pFuncAddr + 1 + idx * DOWN) == 0x8b
                            && *((PBYTE)pFuncAddr + 2 + idx * DOWN) == 0xd1
                            && *((PBYTE)pFuncAddr + 3 + idx * DOWN) == 0xb8
                            && *((PBYTE)pFuncAddr + 6 + idx * DOWN) == 0x00
                            && *((PBYTE)pFuncAddr + 7 + idx * DOWN) == 0x00)
                        {
                            __builtin_memcpy(&wSyscall, ((PBYTE)pFuncAddr + 4 + idx * DOWN), 2);
                            return wSyscall;
                        }

                        if (*((PBYTE)pFuncAddr + idx * UP) == 0x4c
                            && *((PBYTE)pFuncAddr + 1 + idx * UP) == 0x8b
                            && *((PBYTE)pFuncAddr + 2 + idx * UP) == 0xd1
                            && *((PBYTE)pFuncAddr + 3 + idx * UP) == 0xb8
                            && *((PBYTE)pFuncAddr + 6 + idx * UP) == 0x00
                            && *((PBYTE)pFuncAddr + 7 + idx * UP) == 0x00)
                        {
                            __builtin_memcpy(&wSyscall, ((PBYTE)pFuncAddr + 4 + idx * UP), 2);
                            return wSyscall;
                        }
                    }
                    return -1;
                }
            }
        }

        return wSyscall;
    }
}