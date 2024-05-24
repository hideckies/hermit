#include "core/system.hpp"

namespace System::User
{
    std::wstring ComputerNameGet(Procs::PPROCS pProcs)
    {
        WCHAR wInfoBuf[INFO_BUFFER_SIZE] = {'\0'};
        DWORD dwBufCharCount = INFO_BUFFER_SIZE;

        // I think there is no NTAPI to get computer name, so use WINAPI.
        if (!pProcs->lpGetComputerNameW(wInfoBuf, &dwBufCharCount))
        {
            return L"Error: Could not get the computer name.";
        }

        return std::wstring(wInfoBuf);
    }

    std::wstring UserNameGet(Procs::PPROCS pProcs)
    {
        WCHAR wInfoBuf[INFO_BUFFER_SIZE] = {'\0'};
        DWORD dwBufCharCount = INFO_BUFFER_SIZE;

        if (!pProcs->lpGetUserNameW(wInfoBuf, &dwBufCharCount))
        {
            return L"Error: Could not get the username.";
        }

        return std::wstring(wInfoBuf);
    }

    std::vector<std::wstring> AllUsersGet(Procs::PPROCS pProcs)
    {
        std::vector<std::wstring> users = {};

        LPCWSTR lpServerName = NULL;
        LPUSER_INFO_0 pBuf = NULL;
        LPUSER_INFO_0 pTmpBuf;
        DWORD dwEntriesRead = 0;
        DWORD dwTotalEntries = 0;
        DWORD dwResumeHandle = 0;
        DWORD i;
        DWORD dwTotalCount = 0;
        NET_API_STATUS nStatus;
        LPTSTR pszServerName = NULL;

        do
        {
            // nStatus = pProcs->lpNetUserEnum( // I don't know why this is not working...
            nStatus = NetUserEnum(
                lpServerName,
                0,
                FILTER_NORMAL_ACCOUNT, // global users
                (LPBYTE*)&pBuf,
                MAX_PREFERRED_LENGTH,
                &dwEntriesRead,
                &dwTotalEntries,
                &dwResumeHandle
            );

            if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))
            {
                if ((pTmpBuf = pBuf) != NULL)
                {
                    for (i = 0; i < dwEntriesRead; i++)
                    {
                        if (pTmpBuf == NULL)
                        {
                            break;
                        }

                        users.push_back(std::wstring(pTmpBuf->usri0_name));

                        pTmpBuf++;
                        dwTotalCount++;
                    }
                }
            }

            if (pBuf != NULL)
            {
                // pProcs->lpNetApiBufferFree(pBuf);
                NetApiBufferFree(pBuf);
                pBuf = NULL;
            }
        } while (nStatus == ERROR_MORE_DATA);

        if (pBuf != NULL)
        {
            // pProcs->lpNetApiBufferFree(pBuf);
            NetApiBufferFree(pBuf);
            pBuf = NULL;
        }

        return users;
    }
}