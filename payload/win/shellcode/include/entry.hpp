#ifndef HERMIT_ENTRY_HPP
#define HERMIT_ENTRY_HPP

#include "core/nt.hpp"
#include "core/macros.hpp"
#include "core/modules.hpp"
#include "core/procs.hpp"
#include "core/utils.hpp"

#include <windows.h>

#define HASH_KEY 13

#define HASH_KERNEL32DLL				0x6A4ABC5B
#define HASH_NTDLLDLL					0x3CFA685D

#define HASH_LOADLIBRARYA				0xEC0E4E8E
#define HASH_GETPROCADDRESS				0x7C0DFCAA
#define HASH_VIRTUALALLOC				0x91AFCA54
#define HASH_NTFLUSHINSTRUCTIONCACHE	0x534C0AB8

typedef HMODULE (WINAPI * LOADLIBRARYA)( LPCSTR );
typedef FARPROC (WINAPI * GETPROCADDRESS)( HMODULE, LPCSTR );
typedef LPVOID  (WINAPI * VIRTUALALLOC)( LPVOID, SIZE_T, DWORD, DWORD );
typedef DWORD  (NTAPI * NTFLUSHINSTRUCTIONCACHE)( HANDLE, PVOID, ULONG );

typedef ULONG_PTR (WINAPI * REFLECTIVEDLLLOADER)();
typedef BOOL (WINAPI * DLLMAIN)(HINSTANCE, DWORD, LPVOID);

typedef struct
{
	WORD	offset:12;
	WORD	type:4;
} IMAGE_RELOC, *PIMAGE_RELOC;

#pragma intrinsic( _rotr )

__forceinline DWORD rotate(DWORD d)
{
	return _rotr(d, HASH_KEY);
}

__forceinline DWORD hash(char * c)
{
    DWORD h = 0;
	do
	{
		h = rotate(h);
        h += *c;
	} while( *++c );

    return h;
}

extern "C" void AlignRSP();
extern "C" int Entry();

extern "C" LPVOID  ReflectiveCaller();

#endif // HERMIT_ENTRY_HPP