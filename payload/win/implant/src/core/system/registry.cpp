#include "core/system.hpp"

namespace System::Registry
{
    HKEY RegParseRootKey(const std::wstring& wRootKey)
    {
        if (wRootKey == L"HKEY_CLASSES_ROOT" || wRootKey == L"HKCR" || wRootKey == L"hkcr")
        {
            return HKEY_CLASSES_ROOT;
        }
        else if (wRootKey == L"HKEY_CURRENT_CONFIG" || wRootKey == L"HKCC" || wRootKey == L"hkcc")
        {
            return HKEY_CURRENT_CONFIG;
        }
        else if (wRootKey == L"HKEY_CURRENT_USER" || wRootKey == L"HKCU" || wRootKey == L"hkcu")
        {
            return HKEY_CURRENT_USER;
        }
        else if (wRootKey == L"HKEY_LOCAL_MACHINE" || wRootKey == L"HKLM" || wRootKey == L"hklm")
        {
            return HKEY_LOCAL_MACHINE;
        }
        else if (wRootKey == L"HKEY_USERS" || wRootKey == L"HKU" || wRootKey == L"hku")
        {
            return HKEY_USERS;
        }
        else
        {
            return NULL;
        }
    }

    std::vector<std::wstring> RegEnumSubKeys(
        Procs::PPROCS pProcs,
        HKEY hRootKey,
        const std::wstring& wSubKey,
        DWORD dwOptions,
        BOOL bRecursive
    ) {
        std::vector<std::wstring> vSubKeys = {};

        LONG lStatus;
        HKEY hKey = NULL;

        lStatus = pProcs->lpRegOpenKeyExW(
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

        lStatus = pProcs->lpRegQueryInfoKeyW(
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
            pProcs->lpRegCloseKey(hKey);
            return vSubKeys;
        }

        ++dwMaxSubKeyLen; // for null character
        WCHAR name[8192] = {};
        DWORD dwNameLen = 0;

        for (DWORD i = 0; i < dwSubKeys; ++i)
        {
            dwNameLen = dwMaxSubKeyLen;

            lStatus = pProcs->lpRegEnumKeyExW(
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

                if (bRecursive)
                {
                    std::vector<std::wstring> vSubKeys2 = System::Registry::RegEnumSubKeys(
                        pProcs,
                        hRootKey,
                        wNewSubKey,
                        dwOptions,
                        TRUE
                    );
                    vSubKeys.insert(vSubKeys.end(), vSubKeys2.begin(), vSubKeys2.end());
                }
            }
        }

        pProcs->lpRegCloseKey(hKey);

        return vSubKeys;
    }

    BOOL RegAdd(
        Procs::PPROCS   pProcs,
        HKEY            hKeyRoot,
        LPCWSTR         lpSubKey,
        LPCWSTR         lpValueName,
        DWORD           dwType,
        const BYTE      *lpData,
        DWORD           dwDataLen
    ) {
        HKEY hKey;
        DWORD d;
       
        if (pProcs->lpRegCreateKeyExW(
            hKeyRoot,
            lpSubKey,
            0,
            nullptr,
            0,
            KEY_WRITE,
            nullptr,
            &hKey,
            &d
        ) != ERROR_SUCCESS)
        {
            // return L"Error: Failed to create key.";
            return FALSE;
        }

        if (pProcs->lpRegSetValueExW(
            hKey,
            lpValueName,
            0,
            dwType, // REG_SZ,
            lpData, // (BYTE*)lpCmd,
            dwDataLen // (wcslen(lpCmd) + 1) * sizeof(WCHAR)
        ) != ERROR_SUCCESS)
        {
            pProcs->lpRegCloseKey(hKey);
            // return L"Error: Failed to set default value for command of ms-settings.";
            return FALSE;
        }

        pProcs->lpRegCloseKey(hKey);

        return TRUE;
    }
}
