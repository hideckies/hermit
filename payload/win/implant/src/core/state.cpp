#include "core/state.hpp"

namespace State
{
    VOID Free(PSTATE pState)
    {
        // Free allocated buffers of crypto
        Crypt::Cleanup(
            pState->pProcs,
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

        // Free loaded module handlers.
        Modules::Free(pState->pModules);

        delete pState->pCrypt->pAES;
        delete pState->pCrypt;
        delete pState->pProcs;
        // delete pState->pSocket;
        delete pState->pTeb;
        delete pState;
    }
}