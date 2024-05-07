#ifndef HERMIT_CORE_TECHNIQUE_HPP
#define HERMIT_CORE_TECHNIQUE_HPP

#include "core/procs.hpp"
#include "core/system.hpp"

#include <windows.h>
#include <vector>

typedef ULONG_PTR (WINAPI * LPPROC_REFLECTIVEDLLLOADER)();
typedef BOOL (WINAPI * DLLMAIN)(HINSTANCE, DWORD, LPVOID);

#define DEREF(name)*(UINT_PTR *)(name)
#define DEREF_64(name)*(DWORD64 *)(name)
#define DEREF_32(name)*(DWORD *)(name)
#define DEREF_16(name)*(WORD *)(name)
#define DEREF_8(name)*(BYTE *)(name)

namespace Technique::Injection::Helper
{
    DWORD Rva2Offset(DWORD dwRva, UINT_PTR uBaseAddr);
    DWORD GetFuncOffset(LPVOID lpBuffer, LPCSTR lpFuncName);
}

namespace Technique::Injection
{
    // DLL
    BOOL DllInjection(
        Procs::PPROCS       pProcs,
        DWORD               dwPID,
        std::vector<BYTE>   bytes
    );
    BOOL ReflectiveDLLInjection(
        Procs::PPROCS       pProcs,
        DWORD               dwPID,
        std::vector<BYTE>   bytes
    );

    // PE
    BOOL DirectExecution(
        Procs::PPROCS       pProcs,
        std::vector<BYTE>   bytes
    );
    BOOL PEInjection(
        Procs::PPROCS   pProcs
    );
    BOOL ProcessHollowing(
        Procs::PPROCS       pProcs,
        LPVOID              lpBuffer,
        const std::wstring  &wTargetProcess
    );
    
    // Shellcode
    BOOL ShellcodeInjection(
        Procs::PPROCS pProcs,
        DWORD dwPID,
        const std::vector<BYTE>& shellcode
    );
}

#endif //  HERMIT_CORE_TECHNIQUE_HPP