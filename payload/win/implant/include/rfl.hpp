#ifndef HERMIT_RFL_HPP
#define HERMIT_RFL_HPP

#include "hermit.hpp"

#include <windows.h>

typedef BOOL (WINAPI * DLLMAIN)(HINSTANCE, DWORD, LPVOID);

extern "C" LPVOID  ReflectiveCaller();

VOID ResolveIAT(
	LPVOID lpVirtualAddr,
	LPVOID lpIatDir,
	Procs::LPPROC_LOADLIBRARYA lpLoadLibraryA,
    Procs::LPPROC_GETPROCADDRESS lpGetProcAddress
);
VOID ReallocateSections(
	LPVOID lpVirtualAddr,
    LPVOID lpImageBase,
    LPVOID lpBaseRelocDir,
    PIMAGE_NT_HEADERS pNtHeaders
);

#endif // HERMIT_RFL_HPP