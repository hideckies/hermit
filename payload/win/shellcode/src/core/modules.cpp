#include "core/modules.hpp"

namespace Modules
{
    HMODULE GetModuleByName(WCHAR* wModuleName)
    {
        PPEB    pPeb    = nullptr;
        #ifdef _WIN64
            pPeb = (PPEB)__readgsqword(0x60);
        #else
            pPeb = (PPEB)__readfsqword(0x30);
        #endif

        // Get the Ldr pointer
        PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);

        // Get the first entry
        PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

        while (pDte)
        {
            if (pDte->FullDllName.Length != (USHORT)0x0)
            {
                WCHAR* wCurrModuleName = pDte->FullDllName.Buffer;

                SIZE_T i = 0;
                for (i = 0; wCurrModuleName[i] != 0 && wModuleName[i] != 0; i++)
                {
                    WCHAR w1, w2;
                    TO_LOWERCASE(wCurrModuleName[i], w1);
                    TO_LOWERCASE(wModuleName[i], w2);
                    if (w1 != w2) break;
                }

                if (wCurrModuleName[i] == 0 && wModuleName[i] == 0)
                {
                    HMODULE hBase = (HMODULE)(pDte->InInitializationOrderLinks.Flink);
                    return hBase;
                }
            }
            else
                break;

            // Get the next entry
            pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
        }

        return nullptr;
    }
}