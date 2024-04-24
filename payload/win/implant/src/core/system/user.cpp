#include "core/system.hpp"

namespace System::User
{
    std::wstring ComputerNameGet(Procs::PPROCS pProcs)
    {
        WCHAR wInfoBuf[INFO_BUFFER_SIZE] = {'\0'};
        DWORD dwBufCharCount = INFO_BUFFER_SIZE;

        // I think there is no NTAPI to get computer name, so use WINAPI.
        if (!GetComputerNameW(wInfoBuf, &dwBufCharCount))
        {
            return L"Error: Could not get the computer name.";
        }

        return std::wstring(wInfoBuf);
    }

    std::wstring UserNameGet(Procs::PPROCS pProcs)
    {
        WCHAR wInfoBuf[INFO_BUFFER_SIZE] = {'\0'};
        DWORD dwBufCharCount = INFO_BUFFER_SIZE;

        if (!GetUserNameW(wInfoBuf, &dwBufCharCount))
        {
            return L"Error: Could not get the username.";
        }

        return std::wstring(wInfoBuf);
    }

    std::vector<std::wstring> AllUsersGet()
    {
        std::vector<std::wstring> users = {};

        LPUSER_INFO_0 pBuf = NULL;
        LPUSER_INFO_0 pTmpBuf;
        DWORD dwLevel = 0;
        DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
        DWORD dwEntriesRead = 0;
        DWORD dwTotalEntries = 0;
        DWORD dwResumeHandle = 0;
        DWORD i;
        DWORD dwTotalCount = 0;
        NET_API_STATUS nStatus;
        LPTSTR pszServerName = NULL;

        do
        {
            nStatus = NetUserEnum(
                NULL, // (LPCWSTR) pszServerName,
                dwLevel,
                FILTER_NORMAL_ACCOUNT, // global users
                (LPBYTE*)&pBuf,
                dwPrefMaxLen,
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
                NetApiBufferFree(pBuf);
                pBuf = NULL;
            }
        } while (nStatus == ERROR_MORE_DATA);

        if (pBuf != NULL)
        {
            NetApiBufferFree(pBuf);
            pBuf = NULL;
        }

        return users;
    }
}