#include "core/task.hpp"

namespace Task
{
    std::wstring RegQuery(
        State::PSTATE pState,
        const std::wstring& wRootKey,
        const std::wstring& wSubKey,
        BOOL bRecursive
    ) {
        std::wstring result = L"";
        std::vector<std::wstring> vSubKeys = {wSubKey};

        HKEY hRootKey = System::Registry::RegParseRootKey(wRootKey);
        if (hRootKey == NULL)
        {
            return L"Error: Could not get root key.";
        }

        std::vector<std::wstring> vNewSubKeys = System::Registry::RegEnumSubKeys(
            pState->pProcs,
            hRootKey,
            wSubKey,
            KEY_READ,
            bRecursive
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