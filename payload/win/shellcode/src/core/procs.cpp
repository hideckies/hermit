#include "core/procs.hpp"

namespace Procs
{
    PVOID GetProcAddressByName(HANDLE hBase, CONST CHAR* sFuncName, SIZE_T dwFuncNameLen)
    {
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hBase;
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(hBase + pDosHeader->e_lfanew);

        PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(hBase + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        PDWORD pdwFuncNames = (PDWORD)(hBase + pExportDir->AddressOfNames);
        PDWORD pdwFuncAddresses = (PDWORD)(hBase + pExportDir->AddressOfFunctions);
        PWORD pwFuncNameOrdinals = (PWORD)(hBase + pExportDir->AddressOfNameOrdinals);

        for (DWORD i = 0; i < pExportDir->NumberOfFunctions; i++)
        {
            CHAR* pFuncName = (CHAR*)(hBase + pdwFuncNames[i]);

            if (Utils::MemCmp(pFuncName, sFuncName, dwFuncNameLen) == 0)
            {
                PVOID pFuncAddr = (PVOID)(hBase + pdwFuncAddresses[pwFuncNameOrdinals[i]]);
                return pFuncAddr;
            }
        }

        return nullptr;
    }
}