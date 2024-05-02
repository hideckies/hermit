#ifndef HERMIT_REFLECTIVE_HPP
#define HERMIT_REFLECTIVE_HPP

#include "hermit.hpp"

#include <windows.h>

#define DEREF(name)*(UINT_PTR *)(name)
#define DEREF_64(name)*(DWORD64 *)(name)
#define DEREF_32(name)*(DWORD *)(name)
#define DEREF_16(name)*(WORD *)(name)
#define DEREF_8(name)*(BYTE *)(name)

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

extern "C" LPVOID  ReflectiveCaller();

// Additional ----------------------------------------------

// WinDbg> dt -v ntdll!_LDR_DATA_TABLE_ENTRY
//__declspec( align(8) ) 
typedef struct _LDR_DATA_TABLE_ENTRY_R
{
	//LIST_ENTRY InLoadOrderLinks; // As we search from PPEB_LDR_DATA->InMemoryOrderModuleList we dont use the first entry.
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	SHORT LoadCount;
	SHORT TlsIndex;
	LIST_ENTRY HashTableEntry;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY_R, *PLDR_DATA_TABLE_ENTRY_R;

// ---------------------------------------------------------

#endif // HERMIT_REFLECTIVE_HPP