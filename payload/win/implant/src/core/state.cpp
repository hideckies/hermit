#include "core/state.hpp"

namespace State
{
    VOID Free(PSTATE pState)
    {
        // Close HINTERNET handlers.
        System::Http::WinHttpCloseHandles(
            pState->pProcs,
            pState->hSession,
            pState->hConnect,
            pState->hRequest
        );

        // Free loaded modules.
        FreeLibrary(pState->hNTDLL);
        FreeLibrary(pState->hWinHTTPDLL);

        delete pState->pTeb;
        delete pState->pProcs;
        delete pState->pSocket;
        delete pState->pSyscalls;
        delete pState;
    }
}