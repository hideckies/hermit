#include "core/state.hpp"

namespace State
{
     VOID Free(PSTATE pState)
    {
        // Free allocated buffers of crypto
        Crypt::Cleanup(
            pState->pCrypt->pAES->hAlg,
            pState->pCrypt->pAES->hKey,
            pState->pCrypt->pAES->pbKeyObj
        );

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

        delete pState->pCrypt->pAES;
        delete pState->pCrypt;
        // delete pState->pTeb;
        delete pState->pProcs;
        // delete pState->pSocket;
        // delete pState->pSyscalls;
        delete pState;
    }
}