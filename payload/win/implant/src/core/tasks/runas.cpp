#include "core/task.hpp"

namespace Task
{
    std::wstring RunAs(
        const std::wstring& wUser,
        const std::wstring& wPassword,
        const std::wstring& wCmd
    ) {
        STARTUPINFOW si;
        PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si));
        ZeroMemory(&pi, sizeof(pi));
        si.cb = sizeof(si);

        if (!CreateProcessWithLogonW(
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

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        return L"Success: Process created successfully.";
    }
}