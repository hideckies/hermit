#include "core/system.hpp"

namespace System::Process
{
    DWORD GetProcessIdByName(LPCWSTR lpProcessName)
    {
        DWORD pid = 0;
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);
            if (Process32First(hSnapshot, &pe32))
            {
                do
                {
                    if (lstrcmpi(pe32.szExeFile, lpProcessName) == 0)
                    {
                        pid = pe32.th32ProcessID;
                        break;
                    }
                } while (Process32Next(hSnapshot, &pe32));
                
            }
            CloseHandle(hSnapshot);
        }

        return pid;
    }

    std::wstring ExecuteCmd(const std::wstring& cmd)
    {
        std::wstring result;

        SECURITY_ATTRIBUTES sa;
        STARTUPINFOW si;
        PROCESS_INFORMATION pi;
        HANDLE hReadPipe = NULL;
        HANDLE hWritePipe = NULL;
        BOOL bResults = FALSE;

        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.bInheritHandle = TRUE;
        sa.lpSecurityDescriptor = NULL;

        if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0))
        {
            Stdout::DisplayErrorMessageBoxW(L"CreatePipe Error");
            return L"";
        }

        if (!SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0))
        {
            Stdout::DisplayErrorMessageBoxW(L"SetHandleInformation Error");
            return L"";
        }

        ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
        ZeroMemory(&si, sizeof(STARTUPINFOW));

        si.cb = sizeof(STARTUPINFOW);
        si.hStdError = hWritePipe;
        si.hStdOutput = hWritePipe;
        si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
        si.wShowWindow = SW_HIDE;

        // Set application name (full path)
        WCHAR system32Path[MAX_PATH];
        GetSystemDirectoryW(system32Path, MAX_PATH);
        std::wstring wSystem32Path = std::wstring(system32Path);
        const std::wstring applicationName = wSystem32Path + L"\\cmd.exe";
        // const std::wstring applicationName = wSystem32Path + L"\\WindowsPowerShell\\v1.0\powershell.exe";

        // Set command
        std::wstring commandLine = L"/C " + cmd;
        // std::wstring commandLine = L"-c " + cmd;

        bResults = CreateProcessW(
            applicationName.c_str(),
            &commandLine[0],
            NULL,
            NULL,
            TRUE,
            0,
            NULL,
            NULL,
            &si,
            &pi
        );
        if (!bResults)
        {
            Stdout::DisplayErrorMessageBoxW(L"CreateProcessW Error");
            return L"";
        }

        // Read stdout
        DWORD dwRead;
        CHAR chBuf[4096];
        
        CloseHandle(hWritePipe);

        while (ReadFile(hReadPipe, chBuf, 4095, &dwRead, NULL) && dwRead > 0)
        {
            chBuf[dwRead] = '\0';
            result += std::wstring(chBuf, chBuf + dwRead);
        }

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(hReadPipe);

        return result;
    }

    BOOL ExecuteFile(const std::wstring& filePath)
    {
        STARTUPINFO si;
        PROCESS_INFORMATION pi;

        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        ZeroMemory(&pi, sizeof(pi));

        if (!CreateProcess(
            filePath.c_str(),
            NULL,
            NULL,
            NULL,
            FALSE,
            0,
            NULL,
            NULL,
            &si,
            &pi
        ))
        {
            return FALSE;
        }

        WaitForSingleObject(pi.hProcess, INFINITE);

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        return TRUE;
    }
}