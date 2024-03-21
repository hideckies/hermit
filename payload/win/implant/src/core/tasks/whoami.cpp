#include "core/task.hpp"

namespace Task
{
    std::wstring Whoami()
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

    std::wstring WhoamiPriv()
    {
        // Get access token of current process.
        HANDLE hToken;

        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        {
            return L"Error: Failed to open process token.";
        }

        PTOKEN_PRIVILEGES pPrivileges = NULL;
        DWORD dwSize = 0;

        // Determines the received data length.
        if (!GetTokenInformation(hToken, TokenPrivileges, NULL, dwSize, &dwSize))
        {
            if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            {
                return L"Error: Failed to get token information.";
            }
        }

        pPrivileges = (PTOKEN_PRIVILEGES) GlobalAlloc(GPTR, dwSize);

        // Finally get the token information.
        if (!GetTokenInformation(hToken, TokenPrivileges, pPrivileges, dwSize, &dwSize))
        {
            return L"Error: Failed to get token information.";
        }

        TCHAR privName[MAX_PATH];
        DWORD dwPrivNameLen = sizeof(privName);
        DWORD dwReceivedLen = 0;

        std::wstring result;
        std::wstring wFlag;

        for (DWORD i = 0; i < pPrivileges->PrivilegeCount; i++)
        {
            LUID luid = pPrivileges->Privileges[i].Luid;

            dwPrivNameLen = sizeof(privName);
            if (!LookupPrivilegeName(NULL, &luid, privName, &dwPrivNameLen))
            {
                return L"Error: Failed to lookup privilege name.";
                break;
            }

            if (System::Priv::CheckPrivilege(hToken, privName))
            {
                wFlag = L"Enabled";
            }
            else
            {
                wFlag = L"Disabled";
            }

            result += std::wstring(privName) + L"\t\t\t" + wFlag + L"\n";
        }

        if (pPrivileges)
        {
            GlobalFree(pPrivileges);
        }

        return result;
    }
}