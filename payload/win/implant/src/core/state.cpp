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

        // Free loaded modules.
        FreeLibrary(pState->hAdvapi32DLL);
        FreeLibrary(pState->hBcryptDLL);
        FreeLibrary(pState->hCrypt32DLL);
        FreeLibrary(pState->hDbghelpDLL);
        FreeLibrary(pState->hIphlpapiDLL);
        FreeLibrary(pState->hKernel32DLL);
        FreeLibrary(pState->hNetapi32DLL);
        FreeLibrary(pState->hNTDLL);
        FreeLibrary(pState->hShell32DLL);
        FreeLibrary(pState->hUser32DLL);
        FreeLibrary(pState->hWinHTTPDLL);

        delete pState->pCrypt->pAES;
        delete pState->pCrypt;
        delete pState->pTeb;
        delete pState->pProcs;
        // delete pState->pSocket;
        delete pState;
    }
}