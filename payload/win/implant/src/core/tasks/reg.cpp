#include "core/task.hpp"

namespace Task::Helper::Reg
{
    HKEY GetRegRootKey(const std::wstring& wRootKey)
    {
        if (wRootKey == L"HKEY_CLASSES_ROOT" || wRootKey == L"HKCR")
        {
            return HKEY_CLASSES_ROOT;
        }
        else if (wRootKey == L"HKEY_CURRENT_CONFIG" || wRootKey == L"HKCC")
        {
            return HKEY_CURRENT_CONFIG;
        }
        else if (wRootKey == L"HKEY_CURRENT_USER" || wRootKey == L"HKCU")
        {
            return HKEY_CURRENT_USER;
        }
        else if (wRootKey == L"HKEY_LOCAL_MACHINE" || wRootKey == L"HKLM")
        {
            return HKEY_LOCAL_MACHINE;
        }
        else if (wRootKey == L"HKEY_USERS" || wRootKey == L"HKU")
        {
            return HKEY_USERS;
        }
        else
        {
            return NULL;
        }
    }

    std::vector<std::wstring> ListRegSubKeys(
        HKEY hRootKey,
        const std::wstring& wSubKey,
        DWORD dwOptions,
        BOOL bRecurse
    ) {
        std::vector<std::wstring> vSubKeys = {};

        LONG lStatus;
        HKEY hKey = NULL;

        lStatus = RegOpenKeyExW(
            hRootKey,
            wSubKey.c_str(),
            0,
            dwOptions, // KEY_READ,
            &hKey
        );
        if (lStatus != ERROR_SUCCESS)
        {
            return vSubKeys;
        }

        DWORD dwSubKeys;
        DWORD dwMaxSubKeyLen;

        lStatus = RegQueryInfoKeyW(
            hKey,
            NULL,
            NULL,
            NULL,
            &dwSubKeys,
            &dwMaxSubKeyLen,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL
        );
        if (lStatus != ERROR_SUCCESS)
        {
            RegCloseKey(hKey);
            return vSubKeys;
        }

        ++dwMaxSubKeyLen; // for null character
        WCHAR name[BUFFER_SIZE] = {};
        DWORD dwNameLen = 0;

        for (DWORD i = 0; i < dwSubKeys; ++i)
        {
            dwNameLen = dwMaxSubKeyLen;

            lStatus = RegEnumKeyExW(
                hKey,
                i,
                (LPWSTR)&name,
                &dwNameLen,
                NULL,
                NULL,
                NULL,
                NULL
            );
            if (lStatus == ERROR_NO_MORE_ITEMS)
            {
                break;
            }
            if (lStatus == ERROR_SUCCESS)
            {
                std::wstring wName(name);
                std::wstring wNewSubKey = wSubKey + L"\\" + wName;
                vSubKeys.push_back(wNewSubKey);

                if (bRecurse)
                {
                    std::vector<std::wstring> vSubKeys2 = ListRegSubKeys(
                        hRootKey,
                        wNewSubKey,
                        dwOptions,
                        TRUE
                    );
                    vSubKeys.insert(vSubKeys.end(), vSubKeys2.begin(), vSubKeys2.end());
                }
            }
        }

        RegCloseKey(hKey);

        return vSubKeys;
    }
}



namespace Task
{
    std::wstring RegSubKeys(const std::wstring& wRootKey, const std::wstring& wSubKey, BOOL bRecurse)
    {
        HKEY hRootKey = Task::Helper::Reg::GetRegRootKey(wRootKey);
        if (hRootKey == NULL)
        {
            return L"Error: Could not get root key.";
        }

        std::vector<std::wstring> vSubKeys = Task::Helper::Reg::ListRegSubKeys(
            hRootKey,
            wSubKey,
            KEY_READ,
            bRecurse
        );
        if (vSubKeys.size() == 0)
        {
            return L"SubKeys not found.";
        }

        std::wstring result = L"";

        for(std::wstring wSubKey : vSubKeys)
        {
            result += wRootKey + L"\\" + wSubKey + L"\n";
        }

        return result;
    }

    std::wstring RegValues(const std::wstring& wRootKey, const std::wstring& wSubKey, BOOL bRecurse)
    {
        std::wstring result = L"";
        std::vector<std::wstring> vSubKeys = {wSubKey};

        HKEY hRootKey = Task::Helper::Reg::GetRegRootKey(wRootKey);
        if (hRootKey == NULL)
        {
            return L"Error: Could not get root key.";
        }

        std::vector<std::wstring> vNewSubKeys = Task::Helper::Reg::ListRegSubKeys(
            hRootKey,
            wSubKey,
            KEY_READ,
            bRecurse
        );
        vSubKeys.insert(vSubKeys.end(), vNewSubKeys.begin(), vNewSubKeys.end());

        // Enumerate key values
        LONG lStatus;
        HKEY hKey = NULL;
        for (std::wstring weSubKey : vSubKeys)
        {
            result += wRootKey + L"\\" + weSubKey + L"\n";

            lStatus = RegOpenKeyExW(
                hRootKey,
                weSubKey.c_str(),
                0,
                KEY_READ,
                &hKey
            );
            if (lStatus != ERROR_SUCCESS)
            {
                continue;
            }

            DWORD dwIndex = 0;
            WCHAR valueName[MAX_REG_KEY_LENGTH];
            DWORD dwValueNameLen = MAX_REG_KEY_LENGTH;
            BYTE dataBuffer[BUFFER_SIZE];
            DWORD dwDataSize = sizeof(dataBuffer);
            DWORD dwType;

            do {
                lStatus = RegEnumValueW(
                    hKey,
                    dwIndex,
                    valueName,
                    &dwValueNameLen,
                    0,
                    &dwType,
                    dataBuffer,
                    &dwDataSize
                );

                if (lStatus == ERROR_NO_MORE_ITEMS)
                {
                    break;
                }
                if (lStatus == ERROR_SUCCESS)
                {
                    std::wstring wValueName(valueName);
                    if (wValueName == L"")
                    {
                        wValueName = L"(Default)";
                    }
                    result += L"  " + wValueName + L"\t";

                    std::wstring wType = L"";
                    if (dwType == REG_DWORD)
                    {
                        result += L"REG_DWORD\t";
                        DWORD _dwValue = *reinterpret_cast<DWORD*>(dataBuffer);
                        result += Utils::Convert::DWORDToWstring(_dwValue) + L"\n";
                    }
                    else if (dwType == REG_SZ)
                    {
                        result += L"REG_SZ\t";
                        result += std::wstring(reinterpret_cast<wchar_t*>(dataBuffer), dwDataSize / sizeof(wchar_t)) + L"\n";
                    }
                    else
                    {
                        result += L"\n";
                    }
                }

                dwIndex++;
            } while (1);

            RegCloseKey(hKey);
        }

        if (result == L"")
        {
            result = L"Key values not found.";
        }

        RegCloseKey(hKey);

        return result;
    }
}