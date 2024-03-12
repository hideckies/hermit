#ifndef HERMIT_PEB_HPP
#define HERMIT_PEB_HPP

#include <windows.h>

#ifndef __NTDLL_H__

#ifndef TO_LOWERCASE
#define TO_LOWERCASE(out, c1) (out = (c1 <= 'Z' && c1 >= 'A') ? c1 = (c1 - 'A') + 'a': c1)
#endif

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _PEB_LDR_DATA
{
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID      EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY  InLoadOrderModuleList;
    LIST_ENTRY  InMemoryOrderModuleList;
    LIST_ENTRY  InInitializationOrderModuleList;
    void* BaseAddress;
    void* EntryPoint;
    ULONG   SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG   Flags;
    SHORT   LoadCount;
    SHORT   TlsIndex;
    HANDLE  SectionHandle;
    ULONG   CheckSum;
    ULONG   TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN SpareBool;
    HANDLE Mutant;

    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

#endif // __NTDLL_H__

inline LPVOID GetModuleByName(WCHAR* moduleName)
{
    PPEB peb = NULL;
#if defined(_WIN64)
    peb = (PPEB)__readgsqword(0x60);
#else
    peb = (PPEB)__readfsdword(0x30);
#endif
    PPEB_LDR_DATA ldr = peb->Ldr;
    LIST_ENTRY list = ldr->InLoadOrderModuleList;

    PLDR_DATA_TABLE_ENTRY Flink = *((PLDR_DATA_TABLE_ENTRY*)(&list));
    PLDR_DATA_TABLE_ENTRY currModule = Flink;

    while (currModule != NULL && currModule->BaseAddress != NULL)
    {
        if (currModule->BaseDllName.Buffer == NULL) continue;
        WCHAR* currName = currModule->BaseDllName.Buffer;

        size_t i = 0;
        for (i = 0; moduleName[i] != 0 && currName[i] != 0; i++) {
            WCHAR c1, c2;
            TO_LOWERCASE(c1, moduleName[i]);
            TO_LOWERCASE(c2, currName[i]);
            if (c1 != c2) break;
        }
        if (moduleName[i] == 0 && currName[i] == 0)
        {
            return currModule->BaseAddress;
        }

        currModule = (PLDR_DATA_TABLE_ENTRY)currModule->InLoadOrderModuleList.Flink;
    }
    return NULL;
}

inline LPVOID GetFuncByName(LPVOID module, char* funcName)
{
    IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)module;
    if (idh->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return NULL;
    }
    IMAGE_NT_HEADERS* ntHeaders         = (IMAGE_NT_HEADERS*)((BYTE*)module + idh->e_lfanew);
    IMAGE_DATA_DIRECTORY* exportsDir    = &(ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    if (exportsDir->VirtualAddress == NULL)
    {
        return NULL;
    }

    DWORD expAddr               = exportsDir->VirtualAddress;
    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(expAddr + (ULONG_PTR)module);
    SIZE_T namesCount           = exp->NumberOfNames;

    DWORD funcsListRVA      = exp->AddressOfFunctions;
    DWORD funcNamesListRVA  = exp->AddressOfNames;
    DWORD namesOrdsListRVA  = exp->AddressOfNameOrdinals;

    for (SIZE_T i = 0; i < namesCount; i++) {
        DWORD* nameRVA  = (DWORD*)(funcNamesListRVA + (BYTE*)module + i * sizeof(DWORD));
        WORD* nameIndex = (WORD*)(namesOrdsListRVA + (BYTE*)module + i * sizeof(WORD));
        DWORD* funcRVA  = (DWORD*)(funcsListRVA + (BYTE*)module + (*nameIndex) * sizeof(DWORD));

        LPSTR currName = (LPSTR)(*nameRVA + (BYTE*)module);
        size_t k = 0;
        for (k = 0; funcName[k] != 0 && currName[k] != 0; k++) {
            if (funcName[k] != currName[k]) break;
        }
        if (funcName[k] == 0 && currName[k] == 0) {
            //found
            return (BYTE*)module + (*funcRVA);
        }
    }
    return NULL;
}

#endif // HERMIT_PEB_HPP