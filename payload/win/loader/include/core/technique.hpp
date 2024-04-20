#ifndef HERMIT_CORE_TECHNIQUE_HPP
#define HERMIT_CORE_TECHNIQUE_HPP

#include <windows.h>
#include <string>
#include <vector>

#include "core/procs.hpp"
#include "core/stdout.hpp"
#include "core/system.hpp"

namespace Technique::Injection
{
    BOOL DLLInjection(Procs::PPROCS pProcs, DWORD dwPID, LPVOID lpDllPath, size_t dwDllPathSize);
    BOOL ReflectiveDLLInjection(Procs::PPROCS pProcs, LPCWSTR lpDllPath, size_t dwDllPathSize);

    BOOL ShellcodeInjection(Procs::PPROCS pProcs, DWORD dwPID, const std::vector<BYTE>& shellcode);
    BOOL ShellcodeExecutionViaFibers(Procs::PPROCS pProcs, const std::vector<BYTE>& shellcode);
    BOOL ShellcodeExecutionViaAPCAndNtTestAlert(Procs::PPROCS pProcs, const std::vector<BYTE>& shellcode);
}

#endif // HERMIT_CORE_TECHNIQUE_HPP