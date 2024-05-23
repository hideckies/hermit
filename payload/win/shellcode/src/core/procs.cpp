#include "core/procs.hpp"

namespace Procs
{
    // It's used to calculate hash for modules.
    SEC(text, B) ULONG StringToHashModule(WCHAR* wStr, SIZE_T dwStrLen)
    {
        ULONG  dwHash   = HASH_IV;
        WCHAR* pwStr    = wStr;
        SIZE_T dwCnt    = 0;

        do
        {
            WCHAR c = *pwStr;

            if (!c)
            {
                break;
            }

            // If a character is uppercase, convert it to lowercase.
            if (c >= L'A' && c <= L'Z')
            {
                c += L'a' - L'A';
            }

            dwHash = dwHash * RANDOM_ADDR + c;
            ++pwStr;
            dwCnt++;

            if (dwStrLen > 0 && dwCnt >= dwStrLen)
            {
                break;
            }
        } while (TRUE);

        return dwHash & 0xFFFFFFFF;
    }

    // It's used to calculate hash for functions.
    SEC(text, B) DWORD StringToHashFunc(char* str)
    {
        int c;
        DWORD dwHash = HASH_IV;

        while (c = *str++)
        {
            dwHash = dwHash * RANDOM_ADDR + c;
        }

        return dwHash & 0xFFFFFFFF;
    }

    SEC(text, B) PVOID GetModuleByHash(DWORD dwHash)
    {
        PPEB pPeb = (PPEB)PPEB_PTR;
        PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;

        // Get the first entry
        PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)pLdr->InLoadOrderModuleList.Flink;

        while (pDte)
        {   
            if (StringToHashModule(pDte->BaseDllName.Buffer, pDte->BaseDllName.Length) == dwHash)
            {
                return pDte->DllBase;
            }

            // Get the next entry
            pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
        }

        return nullptr;
    }

    SEC(text, B) PVOID GetProcAddressByHash(HMODULE hModule, DWORD dwHash)
    {
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