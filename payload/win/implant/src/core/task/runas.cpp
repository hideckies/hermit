#include "core/task.hpp"

namespace Task
{
    std::wstring RunAs(
        State::PSTATE       pState,
        const std::wstring& wUser,
        const std::wstring& wPassword,
        const std::wstring& wCmd
    ) {
        STARTUPINFOW si;
        PROCESS_INFORMATION pi;
        RtlZeroMemory(&si, sizeof(si));
        RtlZeroMemory(&pi, sizeof(pi));
        si.cb = sizeof(si);

        // 'RtlCreateUserProcess' might be used instead
        if (!pState->pProcs->lpCreateProcessWithLogonW(
            wUser.c_str(),
            NULL,
            wPassword.c_str(),
            LOGON_WITH_PROFILE,
            NULL,
            const_cast<LPWSTR>(wCmd.c_str()),
            CREATE_UNICODE_ENVIRONMENT,
            NULL,
            NULL,
            &si,
            &pi
        )) {
            return L"Error: Failed to create a process.";
        }

        System::Handle::HandleClose(pState->pProcs, pi.hProcess);
        System::Handle::HandleClose(pState->pProcs, pi.hThread);

        return L"Success: Process created successfully.";
    }
}