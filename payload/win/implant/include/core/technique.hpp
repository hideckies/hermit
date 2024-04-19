#ifndef HERMIT_CORE_TECHNIQUE_HPP
#define HERMIT_CORE_TECHNIQUE_HPP

#include "core/procs.hpp"
#include "core/system.hpp"

#include <windows.h>
#include <vector>

namespace Technique::Injection
{
    BOOL DllInjection(
        Procs::PPROCS   pProcs,
        DWORD           dwPID,
        LPVOID          lpDllPath,
        DWORD           dwDllPathSize
    );
    
    BOOL ShellcodeInjection(
        Procs::PPROCS pProcs,
        DWORD dwPID,
        const std::vector<BYTE>& shellcode
    );
}

#endif //  HERMIT_CORE_TECHNIQUE_HPP