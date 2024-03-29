#ifndef HERMIT_CORE_TECHNIQUE_HPP
#define HERMIT_CORE_TECHNIQUE_HPP

#include <windows.h>
#include <string>
#include <vector>

#include "core/stdout.hpp"

namespace Technique::Injection
{
    BOOL DLLInjection(DWORD dwPID, LPVOID lpDllPath, size_t dwDllPathSize);
    BOOL ReflectiveDLLInjection(LPCWSTR lpDllPath, size_t dwDllPathSize);

    BOOL ShellcodeInjection(DWORD dwPID, const std::vector<BYTE>& shellcode);
    BOOL ShellcodeExecutionViaFibers(const std::vector<BYTE>& shellcode);
    BOOL ShellcodeExecutionViaAPCAndNtTestAlert(const std::vector<BYTE>& shellcode);
}

#endif // HERMIT_CORE_TECHNIQUE_HPP