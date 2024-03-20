#ifndef HERMIT_CORE_EVASION_HPP
#define HERMIT_CORE_EVASION_HPP

#include <windows.h>

namespace Evasion::Injection
{
    BOOL DllInjection(DWORD dwPid, LPVOID lpDllPath, size_t dwDllPathSize);
}

#endif // HERMIT_CORE_EVASION_HPP