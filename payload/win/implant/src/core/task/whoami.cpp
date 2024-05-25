#include "core/task.hpp"

namespace Task
{
    std::wstring Whoami(State::PSTATE pState)
    {
        std::wstring wComputerName = System::User::ComputerNameGet(pState->pProcs);
        if (wComputerName == L"")
        {
            return L"Error: Failed to get the computer name.";
        }

        std::wstring wUserName = System::User::UserNameGet(pState->pProcs);
        if (wUserName == L"")
        {
            return L"Error: Failed to get the username.";
        }
        
        return wComputerName + L"\\" + wUserName;
    }

    // I couldn't get privileges using NTAPIs so use WINAPIs.
    std::wstring WhoamiPriv(State::PSTATE pState)
    {
        // Get access token of current process.
        HANDLE hToken;

        if (!pState->pProcs->lpOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY, &hToken))
        {
            return L"Error: Failed to open process token.";
        }

        PTOKEN_PRIVILEGES pPrivileges = NULL;
        DWORD dwSize = 0;

        // Determines the received data length.
        if (!pState->pProcs->lpGetTokenInformation(hToken, TokenPrivileges, NULL, dwSize, &dwSize))
        {
            if (pState->pProcs->lpGetLastError() != ERROR_INSUFFICIENT_BUFFER)
            {
                return L"Error: Failed to get token information.";
            }
        }

        pPrivileges = (PTOKEN_PRIVILEGES) pState->pProcs->lpGlobalAlloc(GPTR, dwSize);

        // Finally get the token information.
        if (!pState->pProcs->lpGetTokenInformation(hToken, TokenPrivileges, pPrivileges, dwSize, &dwSize))
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
            if (!pState->pProcs->lpLookupPrivilegeNameW(NULL, &luid, privName, &dwPrivNameLen))
            {
                return L"Error: Failed to lookup privilege name.";
                break;
            }

            if (System::Priv::PrivilegeCheck(pState->pProcs, hToken, privName))
            {
                wFlag = L"o";
            }
            else
            {
                wFlag = L"x";
            }

            result += wFlag + L" " + std::wstring(privName) + L"\n";
        }

        if (pPrivileges)
        {
            pState->pProcs->lpGlobalFree(pPrivileges);
        }

        return result;
    }
}