#include "core/system.hpp"

namespace System::User
{
    std::wstring GetAccountName()
    {
        std::wstring result;

        WCHAR wInfoBuf[INFO_BUFFER_SIZE] = {'\0'};
        DWORD dwBufCharCount = INFO_BUFFER_SIZE;

        if (!GetComputerNameW(wInfoBuf, &dwBufCharCount))
        {
            return L"Error: Could not get the computer name.";
        }

        result += std::wstring(wInfoBuf);
        dwBufCharCount = INFO_BUFFER_SIZE;
        
        if (!GetUserNameW(wInfoBuf, &dwBufCharCount))
        {
            return L"Error: Could not get the username.";
        }

        result += std::wstring(L"\\");
        result += std::wstring(wInfoBuf);

        return result;
    }

    std::wstring GetSID()
    {
        // Get access token of current process.
        HANDLE hToken;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        {
            return L"Error: Failed to open process token.";
        }

        DWORD dwLengthNeeded;
        if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &dwLengthNeeded) && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            CloseHandle(hToken);
            return L"";
        }

        PTOKEN_USER pTokenUser = (PTOKEN_USER)GlobalAlloc(GPTR, dwLengthNeeded);
        if (!pTokenUser)
        {
            CloseHandle(hToken);
            return L"";
        }

        if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwLengthNeeded, &dwLengthNeeded))
        {
            GlobalFree(pTokenUser);
            CloseHandle(hToken);
            return L"";
        }

        CloseHandle(hToken);

        LPWSTR pSidStr = NULL;
        if (!ConvertSidToStringSidW(pTokenUser->User.Sid, &pSidStr))
        {
            GlobalFree(pTokenUser);
            return L"";
        }

        GlobalFree(pTokenUser);

        return std::wstring(pSidStr);
    }

    std::vector<std::wstring> GetAllUsers()
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