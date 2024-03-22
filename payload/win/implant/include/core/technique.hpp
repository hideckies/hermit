#ifndef HERMIT_CORE_TECHNIQUE_HPP
#define HERMIT_CORE_TECHNIQUE_HPP

#include <windows.h>
#include <vector>

namespace Technique::Injection
{
    BOOL DllInjection(DWORD dwPid, LPVOID lpDllPath, size_t dwDllPathSize);
    BOOL ShellcodeInjection(DWORD dwPid, const std::vector<BYTE>& shellcode);
}

#endif //  HERMIT_CORE_TECHNIQUE_HPP