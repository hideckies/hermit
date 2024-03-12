#ifndef HERMIT_INJECT_HPP
#define HERMIT_INJECT_HPP

#include <windows.h>
#include "common.hpp"

BOOL DllInjection(DWORD dwPid, LPVOID lpDllPath, size_t dwDllPathSize);

#endif // HERMIT_INJECT_HPP