#include "core/task.hpp"

namespace Task
{
    std::wstring Whoami()
    {
        std::wstring wAccountName = System::User::UserAccountNameGet();
        if (wAccountName == L"")
        {
            return L"Error: Failed to get the account name.";
        }
        
        return wAccountName;
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

            if (System::Priv::PrivilegeCheck(hToken, privName))
            {
                // wFlag = L"Enabled";
                wFlag = L"o";
            }
            else
            {
                // wFlag = L"Disabled";
                wFlag = L"x";
            }

            result += wFlag + L" " + std::wstring(privName) + L"\n";
        }

        if (pPrivileges)
        {
            GlobalFree(pPrivileges);
        }

        return result;
    }
}