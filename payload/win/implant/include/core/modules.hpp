#ifndef HERMIT_CORE_MODULES_HPP
#define HERMIT_CORE_MODULES_HPP

#include "core/nt.hpp"
#include "core/procs.hpp"

#include <windows.h>
#include <ntstatus.h>

namespace Modules
{
    struct MODULES
    {
        HMODULE hAdvapi32;
        HMODULE hBcrypt;
        HMODULE hCrypt32;
        HMODULE hDbghelp;
        HMODULE hIphlpapi;
        HMODULE hKernel32;
        HMODULE hNetapi32;
        HMODULE hNtdll;
        HMODULE hShell32;
        HMODULE hUser32;
        HMODULE hWinHttp;
        HMODULE hWs2_32;
    };

    typedef MODULES *PMODULES;

    ULONG StringToHashModule(WCHAR* wStr, SIZE_T dwStrLen);
    PVOID GetModuleByHash(DWORD dwHash);
    PVOID LoadModule(Procs::PPROCS pProcs, LPWSTR lpDllName);
    VOID Free(PMODULES pModules, Procs::PPROCS pProcs);
}

#endif // HERMIT_CORE_MODULES_HPP