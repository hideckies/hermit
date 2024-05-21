#ifndef HERMIT_RFL_HPP
#define HERMIT_RFL_HPP

#include "hermit.hpp"

#include <windows.h>

#define HASH_KERNEL32DLL	0x6A4ABC5B
#define HASH_NTDLLDLL		0x3CFA685D

typedef ULONG_PTR (WINAPI * REFLECTIVEDLLLOADER)();
typedef BOOL (WINAPI * DLLMAIN)(HINSTANCE, DWORD, LPVOID);

extern "C" LPVOID  ReflectiveCaller();

#endif // HERMIT_RFL_HPP