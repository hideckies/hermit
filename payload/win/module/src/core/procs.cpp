#include "core/procs.hpp"

namespace Procs
{
    DWORD StringToHashFunc(char* str)
    {
        int c;
        DWORD dwHash = HASH_IV;

        while (c = *str++)
        {
            dwHash = dwHash * RANDOM_ADDR + c;
        }

        return dwHash & 0xFFFFFFFF;
    }

    PVOID GetProcAddressByHash(
        HMODULE hModule,
        DWORD   dwHash
    ) {
        PVOID pFuncAddr = nullptr;

        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)hModule + pDosHeader->e_lfanew);

        PIMAGE_EXPORT_DIRECTORY pExportDirRVA = (PIMAGE_EXPORT_DIRECTORY)(
            (DWORD_PTR)hModule + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
        );

        PDWORD pdwAddrOfFuncsRVA = (PDWORD)((DWORD_PTR)hModule + pExportDirRVA->AddressOfFunctions);
        PDWORD pdwAddrOfNamesRVA = (PDWORD)((DWORD_PTR)hModule + pExportDirRVA->AddressOfNames);
        PWORD pdwAddrOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)hModule + pExportDirRVA->AddressOfNameOrdinals);

        for (DWORD i = 0; i < pExportDirRVA->NumberOfFunctions; i++)
        {
            DWORD dwFuncNameRVA = pdwAddrOfNamesRVA[i];
            DWORD_PTR dwpFuncNameRVA = (DWORD_PTR)hModule + dwFuncNameRVA;
            char* sFuncName = (char*)dwpFuncNameRVA;
            DWORD_PTR dwpFuncAddrRVA = 0;

            DWORD dwFuncNameHash = StringToHashFunc(sFuncName);
            if (dwFuncNameHash == dwHash)
            {
                dwpFuncAddrRVA = pdwAddrOfFuncsRVA[pdwAddrOfNameOrdinalsRVA[i]];
                pFuncAddr = (PVOID)((DWORD_PTR)hModule + dwpFuncAddrRVA);
                return pFuncAddr;
            }
        }

        return nullptr;
    }
}