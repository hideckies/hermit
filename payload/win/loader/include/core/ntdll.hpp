#ifndef HERMIT_CORE_NTDLL_H
#define HERMIT_CORE_NTDLL_H

#include <windows.h>

#define NtCurrentProcess() (HANDLE)((HANDLE) - 1)
#define NtCurrentProcessId() (NtCurrentTeb()->ClientId.UniqueProcess)
#define NtCurrentProcessToken() ((HANDLE)(LONG_PTR)-4)

#endif // HERMIT_CORE_NTDLL_H