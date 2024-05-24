#include "core/system.hpp"

namespace System::Group
{
    std::vector<std::wstring> AllGroupsGet(Procs::PPROCS pProcs)
    {
        std::vector<std::wstring> groups = {};

        DWORD dwLevel = 1; // Level 1 returns the names of the local groups.
        LPLOCALGROUP_INFO_1 pLocalGroupInfo = NULL;
        LPLOCALGROUP_INFO_1 pLocalGroupInfoPtr = NULL;
        DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
        DWORD dwEntriesRead = 0;
        DWORD dwTotalEntries = 0;
        PDWORD_PTR pdwResumeHandle = NULL;

        // NET_API_STATUS nStatus = pProcs->lpNetLocalGroupEnum( // This is not working but I don't understand why...
        NET_API_STATUS nStatus = NetLocalGroupEnum(
            NULL,
            dwLevel,
            (LPBYTE*)&pLocalGroupInfo,
            dwPrefMaxLen,
            &dwEntriesRead,
            &dwTotalEntries,
            pdwResumeHandle
        );

        if (nStatus == NERR_Success) {
            pLocalGroupInfoPtr = pLocalGroupInfo;

            for (DWORD i = 0; i < dwEntriesRead; i++) {
                groups.push_back(std::wstring(pLocalGroupInfoPtr->lgrpi1_name));
                pLocalGroupInfoPtr++;
            }

            // pProcs->lpNetApiBufferFree(pLocalGroupInfo);
            NetApiBufferFree(pLocalGroupInfo);
        }

        return groups;
    }
}