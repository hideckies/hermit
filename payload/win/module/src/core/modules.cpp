#include "core/modules.hpp"

namespace Modules
{
    // It's used to calculate hash for modules.
    ULONG StringToHashModule(WCHAR* wStr, SIZE_T dwStrLen)
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
    
    PVOID GetModuleByHash(DWORD dwHash)
    {
        Nt::PTEB pTeb = (Nt::PTEB)NtCurrentTeb();
        // PPEB pPeb = (PPEB)PPEB_PTR;
        Nt::PPEB pPeb = (Nt::PPEB)pTeb->ProcessEnvironmentBlock;
        Nt::PPEB_LDR_DATA pLdr = (Nt::PPEB_LDR_DATA)pPeb->Ldr;

        // Get the first entry
        Nt::PLDR_DATA_TABLE_ENTRY pDte = (Nt::PLDR_DATA_TABLE_ENTRY)pLdr->InLoadOrderModuleList.Flink;

        while (pDte)
        {
            if (StringToHashModule(pDte->BaseDllName.Buffer, pDte->BaseDllName.Length) == dwHash)
            {
                return pDte->DllBase;
            }

            // Get the next entry
            pDte = *(Nt::PLDR_DATA_TABLE_ENTRY*)(pDte);
        }

        return nullptr;
    }
}