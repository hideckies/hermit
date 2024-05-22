#include "core/technique.hpp"

namespace Technique::AntiDebug
{
    // Reference:
    // https://evasions.checkpoint.com/src/Anti-Debug/techniques/debug-flags.html
    VOID StopIfDebug(Procs::PPROCS pProcs)
    {
        // 1. Check with IsDebuggerPresent
        if (pProcs->lpIsDebuggerPresent())
        {
            ExitProcess(-1);
        }

        // 2. Check with CheckRemoteDebuggerPresent
        BOOL bRemoteDebuggerPresent;
        if (pProcs->lpCheckRemoteDebuggerPresent(
            NtCurrentProcess(),
            &bRemoteDebuggerPresent
        ) && bRemoteDebuggerPresent)
        {
            ExitProcess(-1);
        }

        // 3. Check with NtGlobalFlag
        #ifdef _WIN64
        DWORD dwNtGlobalFlag = *(PDWORD)((PBYTE)PPEB_PTR + 0xBC);
        #else
        DWORD dwNtGlobalFlag = *(PDWORD)((PBYTE)PPEB_PTR + 0x68);
        #endif

        if (dwNtGlobalFlag & NT_GLOBAL_FLAG_DEBUGGED)
        {
            ExitProcess(-1);
        }
    }
}