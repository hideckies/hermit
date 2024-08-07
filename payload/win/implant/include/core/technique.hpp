#ifndef HERMIT_CORE_TECHNIQUE_HPP
#define HERMIT_CORE_TECHNIQUE_HPP

#include "core/macros.hpp"
#include "core/procs.hpp"
#include "core/system.hpp"

#include <windows.h>
#include <vector>

typedef BOOL (WINAPI * DLLMAIN)(HINSTANCE, DWORD, LPVOID);

// Used for Anti-Debug
#define FLG_HEAP_ENABLE_TAIL_CHECK   0x10
#define FLG_HEAP_ENABLE_FREE_CHECK   0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40
#define NT_GLOBAL_FLAG_DEBUGGED (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)

namespace Technique::AmsiBypass
{
    BOOL PatchAmsi(Procs::PPROCS pProcs);
}

namespace Technique::AntiDebug
{
    VOID StopIfDebug(Procs::PPROCS pProcs);
}

namespace Technique::EtwBypass
{
    BOOL PatchEtw(Procs::PPROCS pProcs);
}

namespace Technique::Injection::Helper
{
    DWORD Rva2Offset(DWORD dwRva, UINT_PTR uBaseAddr);
    DWORD GetFuncOffset(LPVOID lpBuffer, LPCSTR lpFuncName);
}

namespace Technique::Injection
{
    // DLL
    BOOL DllInjection(
        Procs::PPROCS pProcs,
        DWORD dwPID,
        const std::vector<BYTE>& bytes
    );
    BOOL ReflectiveDLLInjection(
        Procs::PPROCS pProcs,
        DWORD dwPID,
        const std::vector<BYTE>& bytes
    );

    // PE
    BOOL DirectExecution(
        Procs::PPROCS pProcs,
        const std::vector<BYTE>& bytes
    );
    BOOL ProcessHollowing(
        Procs::PPROCS pProcs,
        const std::wstring& wTargetProcess,
        const std::vector<BYTE>& bytes
    );
    
    // Shellcode
    BOOL ShellcodeInjection(
        Procs::PPROCS pProcs,
        DWORD dwPID,
        const std::vector<BYTE>& bytes
    );
}

#endif //  HERMIT_CORE_TECHNIQUE_HPP