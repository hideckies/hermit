#ifndef HERMIT_RFL_HPP
#define HERMIT_RFL_HPP

#include "hermit.hpp"

#include <windows.h>

#define HASH_KEY 13

#define HASH_KERNEL32DLL				0x6A4ABC5B
#define HASH_NTDLLDLL					0x3CFA685D

typedef ULONG_PTR (WINAPI * REFLECTIVEDLLLOADER)();
typedef BOOL (WINAPI * DLLMAIN)(HINSTANCE, DWORD, LPVOID);

#pragma intrinsic( _rotr )

__forceinline DWORD rotate(DWORD d)
{
	return _rotr(d, HASH_KEY);
}

extern "C" LPVOID  ReflectiveCaller();

#endif // HERMIT_RFL_HPP