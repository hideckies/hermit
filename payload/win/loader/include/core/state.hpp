#ifndef HERMIT_CORE_STATE_HPP
#define HERMIT_CORE_STATE_HPP

#include "core/crypt.hpp"
#include "core/procs.hpp"
#include "core/state.hpp"
#include "core/system.hpp"

#include <windows.h>
#include <winhttp.h>
#include <string>

namespace State
{
    struct STATE
    {
        // Crypto
        Crypt::PCRYPT       pCrypt;

        // Module handlers
        HMODULE             hKernel32DLL;
        HMODULE             hNTDLL;
        HMODULE             hWinHTTPDLL;

        // Procedures loaded dynamatically
        Procs::PPROCS       pProcs;

        // Payload options
        LPCWSTR             lpPayloadType;
        LPCWSTR             lpPayloadTechnique;
        LPCWSTR             lpPayloadProcessToInject;

        // Payload techniques
        BOOL                bIndirectSyscalls;

        // Listener options
        LPCWSTR             lpListenerProto;
        LPCWSTR             lpListenerHost;
        INTERNET_PORT       nListenerPort;

        // Request paths
        LPCWSTR             lpReqPathDownload;

        // WinHTTP handlers
        HINTERNET           hSession;
        HINTERNET           hConnect;
        HINTERNET           hRequest;

        // Initial information (JSON)
        LPCWSTR             lpInfoJSON;
    };

    typedef STATE* PSTATE;

    VOID Free(PSTATE pState);
}

#endif // HERMIT_CORE_STATE_HPP